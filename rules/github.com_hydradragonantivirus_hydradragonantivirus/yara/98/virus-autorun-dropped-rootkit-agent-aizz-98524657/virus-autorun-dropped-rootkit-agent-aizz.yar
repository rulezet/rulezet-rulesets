rule Virus_Autorun_Dropped_Rootkit_Agent_AIZZ {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Dropped.Rootkit.Agent.AIZZ.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd0aa76967fd9bd200a73583e17e170a8d5200c9ff4d3e693cb3295eaefcbe15"

  strings:
    $s1 = "Purple#" fullword ascii
    $s2 = "look ExprI" fullword ascii
    $s3 = "Copy*o" fullword ascii
    $s4 = ">Module!C" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}