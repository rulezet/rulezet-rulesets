rule Virus_Danger_Trojan_Agent_DQQO_7 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.Agent.DQQO_7.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5e0f7423adcea6dfaa4ca0c7e4cf20357ce8c5f5c6222dc69fbf6947152cf30"

  strings:
    $s1 = "qOrders: is defined as the total number of distinct orders for all programs that are a part of Electronic Orders, entered" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}