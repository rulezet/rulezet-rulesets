rule Trojan_Autorun_Dropped_Generic_Dacic_06B5CF0E_A_3A6AA980_31_2 {
  meta:
    description = "datamaliciousorder - file Trojan.Autorun_Dropped.Generic.Dacic.06B5CF0E.A.3A6AA980_31_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5088a9167ed30d60cdafd7b3ffad7062272cc7b8e4c2abdbd9ff9d667aedbe9b"

  strings:
    $s1 = "ORGY!_" fullword ascii
    $s2 = "F{geLd" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}