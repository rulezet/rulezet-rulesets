rule Virus_Hijack_Trojan_Agent_DQQO_188 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_188.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ad8ffb532f92ca2244d81f68d04be7dfb3aacb922baa6193e3f6d2950c8a72f"

  strings:
    $s1 = "'whole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}