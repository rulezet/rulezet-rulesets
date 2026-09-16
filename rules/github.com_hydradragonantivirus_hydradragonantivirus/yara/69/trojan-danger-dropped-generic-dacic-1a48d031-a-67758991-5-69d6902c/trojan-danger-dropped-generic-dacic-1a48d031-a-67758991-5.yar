rule Trojan_Danger_Dropped_Generic_Dacic_1A48D031_A_67758991_5 {
  meta:
    description = "datamaliciousorder - file Trojan.Danger_Dropped.Generic.Dacic.1A48D031.A.67758991_5.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "97f908d78ae67ebb9c278e4ae1501a27b626ebd3c96c9ef6e4aea8645aeddec7"

  strings:
    $s1 = "'America, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii
    $s2 = "Limited, East Point Business Park, Fairview, Dublin 3, Ireland," fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}