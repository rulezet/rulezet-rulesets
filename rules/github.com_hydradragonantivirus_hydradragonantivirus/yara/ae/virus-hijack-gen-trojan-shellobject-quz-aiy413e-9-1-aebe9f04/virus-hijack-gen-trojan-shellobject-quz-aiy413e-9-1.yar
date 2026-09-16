rule Virus_Hijack_Gen_Trojan_ShellObject_quZ_aiy413e_9_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.quZ@aiy413e_9_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "051a009530f04ef9b28126d22c749f956d971724d69ab1aea0a756cf43d1bfda"

  strings:
    $s1 = "tiEd)_" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}