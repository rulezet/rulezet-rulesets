rule Trojan_Autorun_Trojan_GenericKDZ_94847_41_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Trojan.GenericKDZ.94847_41_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1d1c79c160d28750fb15f49595a4d8497b4d30b3f5264e559340c2ff77ab5223"

  strings:
    $s1 = "?IRE_OLSA_V120103_Def_V122304 Page 1 of 11 " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}