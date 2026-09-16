rule Virus_Hijack_GenPack_Backdoor_Hangup_B_316 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_316.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "22123ebcdca658be6b06c5b70452c4534f3da2b8692f7a53a1e1b5380a8fd628"

  strings:
    $s1 = ":9to be invalid or unenforceable, the remaining provisions will remain effective. It is expressly agreed that the terms of this" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}