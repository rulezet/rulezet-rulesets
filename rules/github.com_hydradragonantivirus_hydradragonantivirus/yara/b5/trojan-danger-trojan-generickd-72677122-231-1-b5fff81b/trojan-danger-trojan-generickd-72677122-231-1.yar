rule Trojan_Danger_Trojan_GenericKD_72677122_231_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72677122_231_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "99d7aa91f723e69ada8513e3d72c500515270bcab17ae5c064f75673c3c2791a"

  strings:
    $s1 = "Copyright (C) 1999-2016 Tencent. All Rights Reserved" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}