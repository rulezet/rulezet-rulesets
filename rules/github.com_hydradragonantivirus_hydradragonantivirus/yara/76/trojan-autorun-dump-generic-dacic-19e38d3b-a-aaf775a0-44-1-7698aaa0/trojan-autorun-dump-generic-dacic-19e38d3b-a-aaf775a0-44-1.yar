rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_44_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_44_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ed89bf01d8c72dd43736ef8383ecd992cc42d2b47de1e0d57dd8f87d47e59ce"

  strings:
    $s1 = "*HOUR LICE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}