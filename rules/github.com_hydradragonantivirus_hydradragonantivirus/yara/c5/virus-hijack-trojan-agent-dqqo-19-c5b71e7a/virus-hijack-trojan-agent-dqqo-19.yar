rule Virus_Hijack_Trojan_Agent_DQQO_19 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_19.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "14408acd54b00a5b70c7d15af9e65bfaf7a4f5063cb678a4d3c3a222a9487b1e"

  strings:
    $s1 = "sABE(AC-C@*,+AB{" fullword ascii
    $s2 = "dProfessional User: is defined as an individual authorized by you to use the application programs which are installed on a" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}