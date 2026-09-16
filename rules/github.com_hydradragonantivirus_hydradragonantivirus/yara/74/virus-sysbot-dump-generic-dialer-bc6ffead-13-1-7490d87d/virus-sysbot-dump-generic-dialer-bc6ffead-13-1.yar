rule Virus_Sysbot_Dump_Generic_Dialer_BC6FFEAD_13_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BC6FFEAD_13_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b75788e19c189d0dc7812665864f62c02f3aef71a031568ccee811afa47e3846"

  strings:
    $s1 = "Qv]JynX#" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}