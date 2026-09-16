rule Virus_Hijack_Gen_Trojan_ShellObject_iuZ_amBwvTb_12_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.iuZ@amBwvTb_12_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5a20a4b1da3b3db02418d235de9c8d83cd9de863e9db4130f09bc5aee68c3cbc"

  strings:
    $s1 = "Copyright 2020 Google LLC. All rights reserved." fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}