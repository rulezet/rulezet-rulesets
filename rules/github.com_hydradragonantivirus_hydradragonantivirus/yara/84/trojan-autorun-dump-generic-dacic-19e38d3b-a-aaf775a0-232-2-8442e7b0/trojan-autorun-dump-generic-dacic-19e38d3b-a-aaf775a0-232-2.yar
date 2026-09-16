rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_232_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_232_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f83cc49bf021a75fe3e83b75c3c4209d78fae98408e220660a40a3635df3259"

  strings:
    $s1 = "AidE[;" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}