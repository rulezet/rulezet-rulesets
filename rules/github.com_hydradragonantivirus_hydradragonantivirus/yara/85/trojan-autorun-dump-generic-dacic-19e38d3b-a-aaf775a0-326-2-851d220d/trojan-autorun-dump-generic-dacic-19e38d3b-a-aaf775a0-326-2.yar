rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_326_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_326_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "039491c0c423f7c37c4344b4e143d6c7bebed409b38a7b4ca66d6b61d511eefe"

  strings:
    $s1 = "$pENK;S" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}