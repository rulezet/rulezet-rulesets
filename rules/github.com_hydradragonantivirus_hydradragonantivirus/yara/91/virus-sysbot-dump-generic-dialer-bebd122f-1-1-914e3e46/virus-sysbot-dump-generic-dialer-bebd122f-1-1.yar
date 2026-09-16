rule Virus_Sysbot_Dump_Generic_Dialer_BEBD122F_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BEBD122F_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2e5e0dd5e009baca6b35d1ad908a9c95d98fb86e8c0be22d9b2d89be471e96c2"

  strings:
    $s1 = "}{nOwy!~v" fullword ascii
    $s2 = "POrR;z" fullword ascii
    $s3 = "?ElsE;" fullword ascii
    $s4 = "lusT`w" fullword ascii
    $s5 = "%}EveR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}