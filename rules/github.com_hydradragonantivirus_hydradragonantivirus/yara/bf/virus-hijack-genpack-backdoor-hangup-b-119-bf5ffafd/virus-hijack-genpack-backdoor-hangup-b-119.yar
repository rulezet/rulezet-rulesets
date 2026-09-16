rule Virus_Hijack_GenPack_Backdoor_Hangup_B_119 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_119.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ceabd698474459b85a769edcbda932f3b2f2e52803d9351c080d3a6e61b7cb76"

  strings:
    $s1 = "Ecreate this contract that applies to you. You can review linked terms by pasting the forward link into your" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}