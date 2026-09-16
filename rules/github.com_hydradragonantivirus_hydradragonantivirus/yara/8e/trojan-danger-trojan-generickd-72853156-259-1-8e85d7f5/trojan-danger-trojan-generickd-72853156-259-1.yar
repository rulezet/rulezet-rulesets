rule Trojan_Danger_Trojan_GenericKD_72853156_259_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Trojan.GenericKD.72853156_259_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5850f12cf532c82553ac93198eb9267ef8a0e4cb7de073d9ad5f5a33fa6a2c4"

  strings:
    $s1 = "those features in any way that cSysqamqqvaqqdSysqemdlwytSysqemoglnmSysqemvoxutSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaq" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}