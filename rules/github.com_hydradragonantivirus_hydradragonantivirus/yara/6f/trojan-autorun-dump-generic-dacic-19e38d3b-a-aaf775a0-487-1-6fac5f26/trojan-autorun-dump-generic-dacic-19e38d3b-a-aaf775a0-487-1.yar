rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_487_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_487_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a70f206698714c3f3d44c2fccecfa7eb937e9d0e79b0641db38974d3014b67ab"

  strings:
    $s1 = "M!boMB" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}