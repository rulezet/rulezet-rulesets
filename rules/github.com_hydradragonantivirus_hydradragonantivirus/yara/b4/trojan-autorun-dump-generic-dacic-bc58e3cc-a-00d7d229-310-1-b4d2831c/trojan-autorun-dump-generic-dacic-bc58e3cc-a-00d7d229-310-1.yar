rule Trojan_Autorun_Dump_Generic_Dacic_BC58E3CC_A_00D7D229_310_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.BC58E3CC.A.00D7D229_310_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e308b3a6cdc6d098338c60605024532e63b61effb37708cd8eff5e0663bad8e"

  strings:
    $s1 = "pObS K-=" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}