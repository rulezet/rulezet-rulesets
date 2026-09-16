rule Virus_Hijack_Backdoor_Hangup_B_52 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_52.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d550b5dfa4b4b0d94da77357c75b9372115e607a2575843f6bc1e69b19b0deed"

  strings:
    $s1 = "[lyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}