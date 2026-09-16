rule Virus_Hijack_Gen_Trojan_ShellObject_uuZ_amBwvTb_18_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.uuZ@amBwvTb_18_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a6badfea7185d62277f1d0ec1867d36fec8080759ed7bb420a595c5067f8c1b5"

  strings:
    $s1 = "Copyright 2022 Google LLC. All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}