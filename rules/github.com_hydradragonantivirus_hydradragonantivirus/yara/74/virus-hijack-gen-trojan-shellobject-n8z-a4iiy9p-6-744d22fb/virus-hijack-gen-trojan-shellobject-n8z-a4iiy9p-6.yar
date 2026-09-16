rule Virus_Hijack_Gen_Trojan_ShellObject_n8Z_a4IIY9p_6 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.n8Z@a4IIY9p_6.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2b52a9bceeb5a2c19de9ba59fd1589adb199b49539198c7fd53d4f434abca369"

  strings:
    $s1 = "MUDD%H{C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}