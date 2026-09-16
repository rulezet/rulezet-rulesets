rule Virus_Hijack_Trojan_Agent_DQQO_153_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_153_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffedcf5074049fba79ebef101f800907df441595dda2a97b8a135d51a2219228"

  strings:
    $s1 = "W&gauR" fullword ascii
    $s2 = "x@beNA" fullword ascii
    $s3 = "DAli(p" fullword ascii
    $s4 = "V(till" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}