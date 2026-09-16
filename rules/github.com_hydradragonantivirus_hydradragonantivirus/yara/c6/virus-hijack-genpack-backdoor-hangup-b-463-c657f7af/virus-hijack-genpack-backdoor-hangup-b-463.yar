rule Virus_Hijack_GenPack_Backdoor_Hangup_B_463 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_463.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8683a53234d7b4e65cf66fe25d8aeec893d49571f8ac3879ae4465b72d3eb09"

  strings:
    $s1 = "dyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}