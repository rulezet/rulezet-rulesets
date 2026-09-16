rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_300_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_300_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4f2140e8ae032de6996f0fd5fd11b89c42618d3edf07199e6d1fb6642fe79176"

  strings:
    $s1 = "<SaUt&7<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}