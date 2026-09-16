rule Trojan_Autorun__Dump_Generic_Dacic_19E38D3B_A_AAF775A0_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun _Dump.Generic.Dacic.19E38D3B.A.AAF775A0_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5cb8ece83c53d20033e2f1ef814c9080b2463c71eb0aa7de149248366f4c4ad4"

  strings:
    $s1 = "System informations not available!" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}