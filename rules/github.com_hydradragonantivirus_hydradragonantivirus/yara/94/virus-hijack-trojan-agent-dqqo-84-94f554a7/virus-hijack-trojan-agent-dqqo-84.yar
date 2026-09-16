rule Virus_Hijack_Trojan_Agent_DQQO_84 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_84.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e83041fbfe3ea8e0a2bdd80521325596cf5f983b7783160ab56085970eade924"

  strings:
    $s1 = "9orders during any 12 month period." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}