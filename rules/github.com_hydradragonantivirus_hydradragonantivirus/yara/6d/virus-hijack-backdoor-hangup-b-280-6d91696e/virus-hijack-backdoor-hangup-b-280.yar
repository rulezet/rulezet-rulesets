rule Virus_Hijack_Backdoor_Hangup_B_280 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_280.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c5ddabf7641ababe7272c5e7d0de54bcbe08c98e13714fa1bdd4ac8332c49d71"

  strings:
    $s1 = "]SaDe;" fullword ascii
    $s2 = "H)SaMp" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}