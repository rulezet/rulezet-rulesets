rule Virus_Hijack_Trojan_Agent_DQQO_326 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_326.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c195bf6f29dd1c55cb60a46d6f064c71bd5d465a42fabea331095434216223c"

  strings:
    $s1 = "(functionality of the programs. You have 30 days from the delivery date to evaluate these programs. If you decide to use any" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}