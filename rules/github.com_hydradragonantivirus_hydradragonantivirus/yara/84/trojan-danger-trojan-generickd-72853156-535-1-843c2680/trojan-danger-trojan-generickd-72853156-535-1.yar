rule Trojan_Danger_Trojan_GenericKD_72853156_535_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_535_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f7a45cd6be11564753556230f12ab81b4b073de13b59711135a8893b688d2c0"

  strings:
    $s1 = "MOAN&5;o" fullword ascii
    $s2 = "![kELD" fullword ascii
    $s3 = "MZ\"HoiT" fullword ascii
    $s4 = "K#LiNt" fullword ascii
    $s5 = "1`kOFT" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}