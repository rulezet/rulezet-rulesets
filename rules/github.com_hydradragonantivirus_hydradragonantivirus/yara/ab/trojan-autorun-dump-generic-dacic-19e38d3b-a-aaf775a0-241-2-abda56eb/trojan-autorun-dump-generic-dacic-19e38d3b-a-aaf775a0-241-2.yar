rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_241_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_241_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d0de031b5786ec9ac28d7176e9f2d0e5bdbadea26daa7be8581115c51069660"

  strings:
    $s1 = "!HeAP`" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}