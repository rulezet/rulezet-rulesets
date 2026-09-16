rule Virus_Hijack_Gen_Trojan_ShellObject_dWW_aOfWMFe_19 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.dWW@aOfWMFe_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "165d4c584ee85b1a2122fa8d2e450b3f48990a21c5c63bea268e807a08354eaf"

  strings:
    $s1 = "Copyright (C) 2014 Gydftgfefef" fullword wide
    $s2 = "Copyright 2014 XiongHaret" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}