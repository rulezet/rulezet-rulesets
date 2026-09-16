rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_309_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_309_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "818d41cbc4d61d75116232d7fa583a095548605fcdf28768fbef98809691911e"

  strings:
    $s1 = "3,howe:" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}