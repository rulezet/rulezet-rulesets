rule Virus_Hijack_Backdoor_Hangup_B_128 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_128.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fa51fd831b94924151502adc8044d22d526e9d1980307553f9bb7aa95ad013b6"

  strings:
    $s1 = "^%of the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}