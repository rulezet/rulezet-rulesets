rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_310_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_310_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8660bbfc744be160f8a1335536bbceddfd533b6df8f9c8939a63b542fc6ae790"

  strings:
    $s1 = "vleI z" fullword ascii
    $s2 = "JAUk;q" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}