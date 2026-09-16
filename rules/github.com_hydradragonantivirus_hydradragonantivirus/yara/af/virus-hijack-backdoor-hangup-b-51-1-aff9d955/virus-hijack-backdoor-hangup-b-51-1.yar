rule Virus_Hijack_Backdoor_Hangup_B_51_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_51_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0ea0a8b8c8dedcc41724095733f9816f9470321b2dc6fd9c282791a31a8be702"

  strings:
    $s1 = "Mozilla/4.0 (compatible; MSIE 9.0; Windows NT 6.1)" fullword ascii
    $s2 = "BOGY'S GAME ENGINE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}