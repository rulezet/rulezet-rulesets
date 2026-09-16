rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_80_1 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_80_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3c8fca305bb2411b994aeab7eb4dc79fbd857055ed968f3ff9f5ff999215f1eb"

  strings:
    $s1 = "<form " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}