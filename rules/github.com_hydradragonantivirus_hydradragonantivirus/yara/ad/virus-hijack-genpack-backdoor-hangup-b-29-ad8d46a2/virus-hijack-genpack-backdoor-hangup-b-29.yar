rule Virus_Hijack_GenPack_Backdoor_Hangup_B_29 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_29.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0c9d15761bef22af87bb2c122ee671bf0e09efc850bfd9404791a132b48cc3b"

  strings:
    $s1 = "1!to be invalid or unenforceable, the remaining provisions will remain effective. It is expressly agreed that the terms of this" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}