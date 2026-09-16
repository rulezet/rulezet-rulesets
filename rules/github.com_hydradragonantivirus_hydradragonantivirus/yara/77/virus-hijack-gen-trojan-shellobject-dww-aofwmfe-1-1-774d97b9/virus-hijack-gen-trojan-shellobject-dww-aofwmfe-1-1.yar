rule Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c60f67915abb8910d3cafd6ec7171424f61ac62a695a50b806dfb9bf2becd74c"

  strings:
    $s1 = "Copyright (C) 2014 Gydftgfefef" fullword wide
    $s2 = "Copyright 2014 XiongHaret" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}