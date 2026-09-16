rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_239_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_239_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8e040658c0b1a7c0cec038abed722488d3b04aa6bf69dfb65252cb9e2224d9c"

  strings:
    $s1 = "W&:yEat" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}