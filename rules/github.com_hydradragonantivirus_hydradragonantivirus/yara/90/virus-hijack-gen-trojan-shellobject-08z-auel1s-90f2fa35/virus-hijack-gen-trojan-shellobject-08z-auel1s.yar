rule Virus_Hijack_Gen_Trojan_ShellObject_08Z_auel1S {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.08Z@auel1S.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "09bb704a3ec7962b99d8399d329c2a61fdedaf4e551b047889ca8f6054964691"

  strings:
    $s1 = "SxSoftware Assurance." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}