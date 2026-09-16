rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_237_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_237_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "35549eb0851887a95fe6ccad090319177fc08e322942778fb9ef33aac5ff9110"

  strings:
    $s1 = "MElT.}Ou" fullword ascii
    $s2 = "haLE{q" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}