rule Trojan_Danger_Trojan_GenericKD_72853156_436_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_436_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06b61ef008c44c0f0f56c57c1292dbb04b16c03f569c398ffe9082e3a72963cc"

  strings:
    $s1 = "gloP#@" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}