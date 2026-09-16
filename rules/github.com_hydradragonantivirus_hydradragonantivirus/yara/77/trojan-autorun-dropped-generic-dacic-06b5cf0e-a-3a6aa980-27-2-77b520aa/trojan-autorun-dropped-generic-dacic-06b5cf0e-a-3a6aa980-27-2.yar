rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_27_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_27_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73ede485d30a91c88bfc83b5a77db2c2f76c30d189e36caac576adfaf5e2aa6e"

  strings:
    $s1 = "KiNa$CQ" fullword ascii
    $s2 = "aiNt]niI" fullword ascii
    $s3 = "kloP[k" fullword ascii
    $s4 = "IvIn(X" fullword ascii
    $s5 = "ih$flix" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}