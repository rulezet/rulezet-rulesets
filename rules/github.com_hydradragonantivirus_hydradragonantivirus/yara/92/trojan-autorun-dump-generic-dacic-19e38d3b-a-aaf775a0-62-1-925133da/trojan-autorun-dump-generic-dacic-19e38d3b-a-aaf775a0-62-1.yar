rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_62_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_62_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a177240d0b810c5eb549d3ebee5f588760f5616e3ca9344265af7db71ddf079"

  strings:
    $s1 = "5Gactive employee population and not the number of" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}