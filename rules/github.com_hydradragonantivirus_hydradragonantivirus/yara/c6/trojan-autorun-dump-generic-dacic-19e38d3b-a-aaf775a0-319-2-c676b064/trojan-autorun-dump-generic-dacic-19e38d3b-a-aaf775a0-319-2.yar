rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_319_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_319_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fc191b2bb0e0587aad4ffedced8cb1bdc97411f2fadd4e0e3ea721eb29bd069"

  strings:
    $s1 = "gaur!]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}