rule Virus_Hijack_Trojan_Agent_DQQO_394 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.Agent.DQQO_394.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e017af9223ba6f4c002396d7341ec3c22e05c208e4d2f29cea5e2c538c02f01f"

  strings:
    $s1 = "lowhole number for purposes of license quantity requirements." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}