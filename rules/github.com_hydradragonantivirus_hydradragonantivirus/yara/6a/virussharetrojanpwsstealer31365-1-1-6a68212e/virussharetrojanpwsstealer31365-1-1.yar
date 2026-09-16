rule VirusShareTrojanPWSStealer31365_1_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanPWSStealer31365_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ecaca6f4be593855ebd927eb0330f3aab210e313b449278af58b24465106031"

  strings:
    $s1 = "I*sEEM" fullword ascii
    $s2 = "rAsh}m" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}