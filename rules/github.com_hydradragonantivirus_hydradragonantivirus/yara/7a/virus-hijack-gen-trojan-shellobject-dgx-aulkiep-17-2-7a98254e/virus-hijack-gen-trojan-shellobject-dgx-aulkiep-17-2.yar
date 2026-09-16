rule Virus_Hijack_Gen_Trojan_ShellObject_dGX_aulKiep_17_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dGX@aulKiep_17_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ab2ca42078f2e9ccd6e1a6e7189d9035189608766a69b6161a20b6d7b0f291c"

  strings:
    $s1 = "hE<CyMe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}