rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_45_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_45_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a986d9192e2d88910a3f1546553cfe7b2e78c129581040ef3f95a7109fb041e"

  strings:
    $s1 = "Gamp!V" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}