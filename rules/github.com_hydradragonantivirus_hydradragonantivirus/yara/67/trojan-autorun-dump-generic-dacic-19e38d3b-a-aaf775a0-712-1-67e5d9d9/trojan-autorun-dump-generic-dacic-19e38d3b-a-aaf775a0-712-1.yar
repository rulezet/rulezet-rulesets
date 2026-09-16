rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_712_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_712_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d04d26f230715260ae87bd9d84645a702afa419c1c8bfa175a74cbbee67fd895"

  strings:
    $s1 = "qiLearning Subscription: is defined as a web base" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}