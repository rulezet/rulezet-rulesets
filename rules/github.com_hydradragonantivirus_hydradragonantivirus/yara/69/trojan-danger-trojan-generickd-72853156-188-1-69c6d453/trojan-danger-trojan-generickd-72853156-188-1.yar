rule Trojan_Danger_Trojan_GenericKD_72853156_188_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_188_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5e702470aae0dd70e13f1b47d24136fd8593783d8574a3c7788e9c9b1286309"

  strings:
    $s1 = "Copyright 2014 SongHaret" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}