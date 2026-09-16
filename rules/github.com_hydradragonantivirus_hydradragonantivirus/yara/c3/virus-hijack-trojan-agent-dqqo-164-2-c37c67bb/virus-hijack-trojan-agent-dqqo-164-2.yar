rule Virus_Hijack_Trojan_Agent_DQQO_164_2 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_164_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d84a78255fa18c5bc0f6705b7b2ae85d2a0e0d98eda7026c95f3fde80f72053c"

  strings:
    $s1 = "Windows File Protection" fullword ascii
    $s2 = "(3}Rich" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}