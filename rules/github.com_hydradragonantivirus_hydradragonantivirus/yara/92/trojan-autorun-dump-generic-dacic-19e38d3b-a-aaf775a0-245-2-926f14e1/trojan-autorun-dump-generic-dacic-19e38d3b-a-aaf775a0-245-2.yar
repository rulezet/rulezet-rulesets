rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_245_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_245_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ad0cceb94261402954a54fc8beea833255e9a937272bb213442dcc5d14ea3ab6"

  strings:
    $s1 = "jAwY`0" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}