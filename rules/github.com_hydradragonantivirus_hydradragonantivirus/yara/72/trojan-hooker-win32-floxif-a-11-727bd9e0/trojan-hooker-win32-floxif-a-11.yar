rule Trojan_Hooker_Win32_Floxif_A_11 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19fd60f815b43ea536394f1c44e966a9f1fd4d05257270af25675c0d3aeea82b"

  strings:
    $s1 = "ions Copyright (c) 1983,97 " fullword ascii
    $s2 = "HEft[HN" fullword ascii
    $s3 = "&JEFf?" fullword ascii
    $s4 = "s'!Share" fullword ascii
    $s5 = "tauM;=" fullword ascii
    $s6 = "bibB{Q" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}