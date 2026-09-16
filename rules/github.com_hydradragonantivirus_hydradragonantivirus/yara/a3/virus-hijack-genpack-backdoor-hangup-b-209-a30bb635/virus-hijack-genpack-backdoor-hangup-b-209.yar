rule Virus_Hijack_GenPack_Backdoor_Hangup_B_209 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_209.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "db6087e78a4b7bcdcb9ea6e7512bec6845751610d41be38b937bea91bd6b559b"

  strings:
    $s1 = "D#your entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}