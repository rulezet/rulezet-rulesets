rule Virus_Hijack_Trojan_Agent_CPGE {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.CPGE.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9cb0004f43e61aedce83f8c31bcbb6320cb5b70e3e11690b77f24cf5f854e4e"

  strings:
    $s1 = "Color@&B" fullword ascii
    $s2 = "Height,%B" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}