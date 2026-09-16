rule Virus_Hijack_GenPack_Backdoor_Hangup_B_193 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_GenPack.Backdoor.Hangup.B_193.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12f871d2cce2068d575754c3ebbbf5b6b31549da268b6c4274a8ca919fb04673"

  strings:
    $s1 = "5the licensed computer, with the Certificate of Authenticity label, and this agreement. Before the transfer," fullword ascii
    $s2 = "WhaU[8" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}