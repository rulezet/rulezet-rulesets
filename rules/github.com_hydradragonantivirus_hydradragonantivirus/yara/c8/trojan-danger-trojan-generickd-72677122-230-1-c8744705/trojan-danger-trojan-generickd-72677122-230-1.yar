rule Trojan_Danger_Trojan_GenericKD_72677122_230_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_230_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5d50972c86148c55f746655709b6dd1f295508cb7b0cb597f21c2e30ad06d0c9"

  strings:
    $s1 = "Copyright (C) 1999-2016 Tencent. All Rights Reserved" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}