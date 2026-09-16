rule Virus_Sysbot_Dump_Generic_Dialer_BC6FFEAD_23_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BC6FFEAD_23_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "405334dc5f85217d90c936b2efe331e4a1136239f26bab90c8c8b38fc9b64120"

  strings:
    $s1 = "FElty$" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}