rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_305_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_305_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d90d98f5e10d797aca9260c892f15bba3fb24a369e0e9cb7be570f011c837f35"

  strings:
    $s1 = "Hako&kq" fullword ascii
    $s2 = "BARB@D" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}