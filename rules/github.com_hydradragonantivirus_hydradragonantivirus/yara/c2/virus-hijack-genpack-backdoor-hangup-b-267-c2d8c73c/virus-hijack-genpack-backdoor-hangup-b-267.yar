rule Virus_Hijack_GenPack_Backdoor_Hangup_B_267 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_267.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5154ea32912ec41b5e2b99114ef6110701d9034567486c00ce420507bd99cf56"

  strings:
    $s1 = ") as well as such courses `" fullword ascii
    $s2 = "-to be invalid or unenforceable, the remaining provisions will remain effective. It is expressly agreed that the terms of this" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}