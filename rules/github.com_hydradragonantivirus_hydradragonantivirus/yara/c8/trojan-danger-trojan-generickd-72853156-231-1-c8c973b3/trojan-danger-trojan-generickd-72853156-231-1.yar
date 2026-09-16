rule Trojan_Danger_Trojan_GenericKD_72853156_231_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_231_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70aee4e74305ba09d401dbc318181e3bb7955e7e9423ddbc21649c8ac7a8cd62"

  strings:
    $s1 = "those features in any way that cSysqamqqvaqqdSysqemdlwytSysqemoglnmSysqemvoxutSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaq" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}