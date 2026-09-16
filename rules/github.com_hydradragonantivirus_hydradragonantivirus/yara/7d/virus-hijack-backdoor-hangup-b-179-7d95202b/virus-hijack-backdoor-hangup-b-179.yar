rule Virus_Hijack_Backdoor_Hangup_B_179 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_179.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "05aeb7e33285877f382669822f6cd8fc12fa29911e360219cfa440ca8fda436e"

  strings:
    $s1 = "F1create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}