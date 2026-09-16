rule Virus_Autorun_Dropped_Rootkit_Agent_AIZZ_1 {
  meta:
    description = "datamaliciousorder - file Virus.Autorun_Dropped.Rootkit.Agent.AIZZ_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0bff9a3f616c2749ac3aa9f252e8c533e3a7511bddf58b532323b12d7f054466"

  strings:
    $s1 = "ODBC Data Sources (32-bit).lnk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}