rule Trojan_Hooker_Win32_Floxif_A_46 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_46.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2de48b96e6417754f4417ad7eb0c8b649d02c0220234702a30babc26d5bd435"

  strings:
    $s1 = "Copyright 2006-2014 iTianKong.com, all rights reserved." fullword wide
    $s2 = "tEAl:a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}