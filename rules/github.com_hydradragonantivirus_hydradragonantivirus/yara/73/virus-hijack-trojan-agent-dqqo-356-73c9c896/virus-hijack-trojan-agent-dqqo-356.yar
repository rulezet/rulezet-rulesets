rule Virus_Hijack_Trojan_Agent_DQQO_356 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_356.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "85953d7efba15601a19a5a7742df882a7e6fe05aaabfae81115124215dd2b83a"

  strings:
    $s1 = "&automatically sign you into the software using the same Microsoft account. This allows you to store and" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}