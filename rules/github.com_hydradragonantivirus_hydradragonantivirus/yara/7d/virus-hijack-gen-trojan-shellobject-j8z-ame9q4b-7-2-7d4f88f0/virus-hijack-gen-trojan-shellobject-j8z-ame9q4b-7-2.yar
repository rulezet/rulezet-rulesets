rule Virus_Hijack_Gen_Trojan_ShellObject_J8Z_ame9q4b_7_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.J8Z@ame9q4b_7_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4ea03ebe353a65fa0a4677c28447465d145cc0dd3007561647e2a5863c0f7da"

  strings:
    $s1 = "DEDo#1i" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}