rule Virus_Hijack_Backdoor_Hangup_B_135 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_135.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2ab0e2394ceea447a9ae4f533b6ee870a220f2de8bfc79c4d005dd8bcde59dd7"

  strings:
    $s1 = "\"of the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}