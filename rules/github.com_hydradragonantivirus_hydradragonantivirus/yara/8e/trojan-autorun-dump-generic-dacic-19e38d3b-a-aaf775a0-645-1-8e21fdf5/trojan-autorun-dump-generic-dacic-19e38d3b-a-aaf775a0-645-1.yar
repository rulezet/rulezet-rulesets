rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_645_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_645_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db5ef7c1d4a970c58881d8064f17f2a86f8b8d683cf2f555ba953d235a733a11"

  strings:
    $s1 = "8If you want to find out more about academic soft" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}