rule Virus_Danger_Trojan_Agent_DQQO_15 {
  meta:
    description = "datamaliciousorder - file Virus.Danger_Trojan.Agent.DQQO_15.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79e61f2ac6ede2fe8069c28e68cadbe1a8df0a340551bc16f5a90858186cf77c"

  strings:
    $s1 = "dAmerica, call (800) MICROSOFT or see microsoft.com/info/nareturns.htm." fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}