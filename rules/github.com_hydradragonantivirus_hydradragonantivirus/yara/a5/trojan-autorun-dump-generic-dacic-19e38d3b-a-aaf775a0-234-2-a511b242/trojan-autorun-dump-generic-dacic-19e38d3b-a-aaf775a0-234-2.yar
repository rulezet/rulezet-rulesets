rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_234_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_234_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fcddbd6e9d779cef4ba9135a677bfb20d90493a168b8402492aa1a7d3f38a1a3"

  strings:
    $s1 = "(DECK}:S" fullword ascii
    $s2 = "huLA&#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}