rule Virus_Hijack_Backdoor_Hangup_B_290 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_290.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1fec314b606c1fb8071c3709573b1f71924229b746caceb1edf8ddeb2960e331"

  strings:
    $s1 = "Eto be invalid or unenforceable, the remaining provisions will remain effective. It is expressly agreed that the terms of this" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}