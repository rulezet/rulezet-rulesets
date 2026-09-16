rule Virus_Sysbot_Dump_Generic_Dialer_BC6FFEAD_6_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BC6FFEAD_6_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a0eba47db0ba2d950931dfa1c5afda05d35cf75a20c8bb1394a35d7d8b79c8c"

  strings:
    $s1 = "}brat{" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}