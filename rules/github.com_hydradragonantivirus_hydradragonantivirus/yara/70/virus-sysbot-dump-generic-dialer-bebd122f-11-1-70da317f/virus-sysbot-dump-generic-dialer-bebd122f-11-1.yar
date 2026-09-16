rule Virus_Sysbot_Dump_Generic_Dialer_BEBD122F_11_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BEBD122F_11_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "950e5babf71b40d3d5fd0278d852b222c1caa8ae884a4ef6b621b84528e2add6"

  strings:
    $s1 = "r>'j*MiAs]" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}