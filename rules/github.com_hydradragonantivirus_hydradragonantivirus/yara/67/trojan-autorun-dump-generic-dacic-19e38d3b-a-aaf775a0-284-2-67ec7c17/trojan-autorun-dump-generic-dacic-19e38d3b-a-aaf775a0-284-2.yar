rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_284_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_284_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7d7b1cc7058ef64ec792020aef3e0d75bb408838153c304b1325cec229479fe"

  strings:
    $s1 = "faZe&>" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}