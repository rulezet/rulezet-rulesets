rule Virus_Sysbot_Dump_Generic_Dialer_5485D7ED_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.5485D7ED_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b6c3f1bea9dfac5e463d4a14ab9fb1a93c3df1313023727fb91c45bdb9fc383b"

  strings:
    $s1 = "ANAy@[" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}