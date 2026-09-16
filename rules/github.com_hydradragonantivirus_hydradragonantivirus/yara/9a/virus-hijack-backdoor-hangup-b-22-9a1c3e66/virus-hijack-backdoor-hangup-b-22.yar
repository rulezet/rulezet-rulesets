rule Virus_Hijack_Backdoor_Hangup_B_22 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_22.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "67e57de8767b35f74a4259327d49d5c2f304320cd821e4fe2ed702d3cd483113"

  strings:
    $s1 = "%of the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}