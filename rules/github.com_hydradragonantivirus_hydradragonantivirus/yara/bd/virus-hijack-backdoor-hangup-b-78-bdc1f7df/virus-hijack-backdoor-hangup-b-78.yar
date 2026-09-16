rule Virus_Hijack_Backdoor_Hangup_B_78 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_78.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bf04657fe357d38c93f408c2f1f0357b3bc3eff594bdfa1ac5ef4a449bd5d55"

  strings:
    $s1 = ":Ccreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}