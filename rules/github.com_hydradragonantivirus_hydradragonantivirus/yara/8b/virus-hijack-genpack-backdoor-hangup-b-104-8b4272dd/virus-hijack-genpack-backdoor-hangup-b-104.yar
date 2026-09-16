rule Virus_Hijack_GenPack_Backdoor_Hangup_B_104 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_104.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca7375828f5a2699cfa2df39c6ce11cda9d0a349a5ae59dafe396b4d5d3cf207"

  strings:
    $s1 = "Vyour entire employee population." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}