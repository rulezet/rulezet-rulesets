rule Virus_Hijack_Backdoor_Hangup_B_134 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Backdoor.Hangup.B_134.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7fcb4ffd5dbbd29b4337209829ce15da961f2512909c9c4d615b25661c4053e4"

  strings:
    $s1 = "dcreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}