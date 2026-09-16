rule Virus_Hijack_Backdoor_Hangup_B_102 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_102.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2212719c714df839d9c5340638243bef77a1e1a209d3fd58c68b51c3167c4628"

  strings:
    $s1 = "$of the software and a separate license for each copy. Content protected by digital rights management" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}