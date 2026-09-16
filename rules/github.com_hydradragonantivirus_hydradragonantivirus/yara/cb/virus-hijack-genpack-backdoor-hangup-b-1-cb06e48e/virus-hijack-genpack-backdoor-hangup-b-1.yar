rule Virus_Hijack_GenPack_Backdoor_Hangup_B_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bd3842489caf00cd8a31fea6b9e56f6d273602a827ed72a7ebf921b856fc7de2"

  strings:
    $s1 = "D{dHaN" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}