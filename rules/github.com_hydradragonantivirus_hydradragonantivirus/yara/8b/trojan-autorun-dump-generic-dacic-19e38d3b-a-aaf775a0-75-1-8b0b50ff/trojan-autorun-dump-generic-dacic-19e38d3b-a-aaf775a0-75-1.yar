rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_75_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_75_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6b5b95f1e5117bd29a22f54ae39697063292658807fce9ed699f810fc768cd3"

  strings:
    $s1 = "Lare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}