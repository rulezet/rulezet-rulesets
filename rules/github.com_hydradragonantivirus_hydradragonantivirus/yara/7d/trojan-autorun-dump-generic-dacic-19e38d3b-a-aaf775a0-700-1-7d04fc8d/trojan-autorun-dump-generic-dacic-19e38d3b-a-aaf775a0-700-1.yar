rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_700_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_700_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "665a27bc247055a884586de804abafb1e7a1c018bece19e944fa3116d31aede6"

  strings:
    $s1 = "rAni'y" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}