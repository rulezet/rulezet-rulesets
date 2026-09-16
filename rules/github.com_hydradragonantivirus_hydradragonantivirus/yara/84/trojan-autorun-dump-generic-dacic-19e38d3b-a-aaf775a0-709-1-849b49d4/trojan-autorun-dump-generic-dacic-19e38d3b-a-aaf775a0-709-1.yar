rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_709_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_709_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "792f9e90f11c510f522cebf02aab52cafbf2cd02cbf40a18e121731c776731e0"

  strings:
    $s1 = "8kprevent either party from disclosing the terms o" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}