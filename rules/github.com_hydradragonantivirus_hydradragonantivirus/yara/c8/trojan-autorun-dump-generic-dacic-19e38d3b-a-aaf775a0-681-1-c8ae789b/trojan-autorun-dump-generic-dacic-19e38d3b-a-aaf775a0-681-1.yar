rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_681_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_681_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b7b9c45d1fdaa275fa87b23f80b376675a82462100bd284ae47a775c2468e642"

  strings:
    $s1 = "Vare a part of the software and may not be used s" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}