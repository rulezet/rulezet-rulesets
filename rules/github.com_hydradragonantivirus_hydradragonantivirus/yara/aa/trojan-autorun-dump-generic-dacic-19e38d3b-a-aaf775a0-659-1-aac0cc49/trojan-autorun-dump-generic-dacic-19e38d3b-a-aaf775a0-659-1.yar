rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_659_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_659_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "218d5f0c85bf0f6ab7411780591de2264e2e180451499ad8cc5947120e00272e"

  strings:
    $s1 = "=You may temporarily download the fonts to a prin" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}