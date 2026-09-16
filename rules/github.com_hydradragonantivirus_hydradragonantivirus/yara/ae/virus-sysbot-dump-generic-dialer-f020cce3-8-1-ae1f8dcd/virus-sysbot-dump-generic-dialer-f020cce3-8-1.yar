rule Virus_Sysbot_Dump_Generic_Dialer_F020CCE3_8_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.F020CCE3_8_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b611c850db41219d1ececbf62a0e974501a35785311fba2f14899412bffc3628"

  strings:
    $s1 = "kU@AGue" fullword ascii
    $s2 = "@ZYGa(" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}