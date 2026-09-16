rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_395_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_395_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1f6b7cc590053ca9aea2179e4ff1b074bd495f605d0543d420395c46a3c157d2"

  strings:
    $s1 = "W\"month pe" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}