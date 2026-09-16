rule Virus_Danger_Gen_Trojan_ShellObject_eSW_aaT6Wyj {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Gen.Trojan.ShellObject.eSW@aaT6Wyj.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3412d9678db0dbf7e4b77b63a6a5695675598fefb547f126ce096bf50b622bb4"

  strings:
    $s1 = "Fwhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}