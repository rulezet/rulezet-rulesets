rule Trojan_Autorun_Generic_Dacic_AAD0835C_A_866F9A53 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Generic.Dacic.AAD0835C.A.866F9A53.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "47f87eb5e526f15251c4c07a7079fd41852159946b7726d30458aa031022f42a"

  strings:
    $s1 = "those features in any way that cSysqamqqvaqqdSysqemdlwytSysqemoglnmSysqemvoxutSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaqqdSysqamqqvaq" ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}