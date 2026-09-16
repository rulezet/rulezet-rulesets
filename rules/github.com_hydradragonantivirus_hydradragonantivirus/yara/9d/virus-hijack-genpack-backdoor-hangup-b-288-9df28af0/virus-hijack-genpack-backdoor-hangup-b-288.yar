rule Virus_Hijack_GenPack_Backdoor_Hangup_B_288 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_288.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5ab49f31d55c1401e560b6811047dac9c571edab161a9151ff3ff362b462f50"

  strings:
    $s1 = "|create this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}