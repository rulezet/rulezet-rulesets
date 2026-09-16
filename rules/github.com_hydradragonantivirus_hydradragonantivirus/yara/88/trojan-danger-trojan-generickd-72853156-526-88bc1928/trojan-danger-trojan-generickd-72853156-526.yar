rule Trojan_Danger_Trojan_GenericKD_72853156_526 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_526.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55ad9d40360e0ae232006df23011152d870ce55b6765e67dcc73994cfb52ecd1"

  strings:
    $s1 = "01 - File Explorer.lnk.exe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}