rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_226_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_226_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "feec78dc46196919174cd5db5fa3cc0c73374e8e7f9bf1d3c7bfd9b5b4bd439e"

  strings:
    $s1 = "DoLE[is" fullword ascii
    $s2 = ">WOlF>r" fullword ascii
    $s3 = "boho;3" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}