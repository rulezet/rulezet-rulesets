rule Trojan_Autorun_Trojan_GenericKD_47942535_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKD.47942535_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e31aa377b32420f7ef247e235c5f968fae9277ae5765c0492977c2e369c6854c"

  strings:
    $s1 = "S\\User, Marketing User, Manufacturing User, Purcha" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}