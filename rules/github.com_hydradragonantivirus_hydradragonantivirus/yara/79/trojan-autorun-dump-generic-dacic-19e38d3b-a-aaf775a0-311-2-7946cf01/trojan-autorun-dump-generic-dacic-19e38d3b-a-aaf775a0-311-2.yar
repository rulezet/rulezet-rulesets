rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_311_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_311_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8004343b31164b07bda32e7ea530c1f89fa895027e51d3cba9ae8e99a3254002"

  strings:
    $s1 = "MoOL#/\"" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}