rule Virus_Sysbot_Dump_Generic_Dialer_BC6FFEAD_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BC6FFEAD_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "031ae5434d22a3d49d87cd2f57a6a7dc11a4a67d5e5ab8785cb7d3a79f114d3f"

  strings:
    $s1 = "Sley@l" fullword ascii
    $s2 = ")uPas(" fullword ascii
    $s3 = "aL!pAnd" fullword ascii
    $s4 = "HaEm&)" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}