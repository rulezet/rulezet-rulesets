rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_81_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_81_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70bbe23697a3237ee96e3eae01c91ec89326bb790838d3e1be456b8a9f3e539d"

  strings:
    $s1 = "Oracle does not warrant that the Oracle Universi" fullword ascii
    $s2 = "Microsoft products. You agree that w`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}