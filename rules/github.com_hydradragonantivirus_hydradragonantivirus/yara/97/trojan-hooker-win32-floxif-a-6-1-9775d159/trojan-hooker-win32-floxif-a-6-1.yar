rule Trojan_Hooker_Win32_Floxif_A_6_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Hooker_Win32.Floxif.A_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03f975daf71d5acc0ea719ac16ccdec022c1d647a2aa0381b317ddaf9d226d37"

  strings:
    $s1 = " in DOS mode." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}