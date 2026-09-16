rule Virus_Hijack_Backdoor_Hangup_B_146 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_146.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0c4a26c8c136c157019f50ab8d5f915f301f3b45018eeb578697cf5212467310"

  strings:
    $s1 = "ujof the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}