rule Trojan_Autorun_Dump_Generic_Dacic_19E38D3B_A_AAF775A0_289_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dump.Generic.Dacic.19E38D3B.A.AAF775A0_289_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8ed377e969c5623fcf52ff2d595b824aab43f34e1e030bd6b7e964eff690a1bb"

  strings:
    $s1 = "L(pert" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}