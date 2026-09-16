rule Trojan_Danger_Dropped_Generic_Dacic_1A48D031_A_67758991 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Dropped.Generic.Dacic.1A48D031.A.67758991.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f489aa004193ca892812c5936745c3328d4d725847a036f3fca862095321ff36"

  strings:
    $s1 = "PROCESSOR_IDENTIFIER=Intel64 Family 6 Model 85 Stepping 7, GenuineIntel" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}