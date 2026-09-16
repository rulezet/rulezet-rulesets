rule Virus_Hijack_Gen_Trojan_ShellObject_q8Z_aCkwazk_3_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.q8Z@aCkwazk_3_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c7de892c9470a319fde3ba7ac0a86617dd4b35a6f9c6106980c121c7f620c126"

  strings:
    $s1 = "JUcK*O(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}