rule Virus_Hijack_Trojan_Agent_DQRC {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQRC.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7b1ad5c5d4927ca931654833268e694d4353ac008ffe6ea3e8173a697620de11"

  strings:
    $s1 = "CRITIC" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}