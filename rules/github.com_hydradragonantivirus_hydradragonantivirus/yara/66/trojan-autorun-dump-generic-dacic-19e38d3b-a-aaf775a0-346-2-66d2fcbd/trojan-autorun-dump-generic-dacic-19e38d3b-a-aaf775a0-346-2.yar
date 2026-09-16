rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_346_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_346_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "615ae4e917dab894699846dc78a8c9daf07fcbe5f4ad06483b8a4a5bd17d9e4e"

  strings:
    $s1 = "Discord Link :  v1.0.0-custom" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}