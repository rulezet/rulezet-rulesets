rule Virus_Hijack_Gen_Trojan_ShellObject_DuZ_amBwvTb_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Gen.Trojan.ShellObject.DuZ@amBwvTb_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b574ef97b4308538ffb29d7b537ee26723df7639fb64f800691807f0572a9ab"

  strings:
    $s1 = "Copyright (C) 2014 Hudfteff" fullword wide
    $s2 = "Copyright 2014 WinngTsdef" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}