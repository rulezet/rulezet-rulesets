rule Virus_Hijack_Gen_Trojan_ShellObject_dyX_a0MYK1d_1_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dyX@a0MYK1d_1_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60c845f999bda6e5b6458ee5624ef72c8fd3c9cb5111ccf1c46acf471cb55a20"

  strings:
    $s1 = "z:ANUS" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}