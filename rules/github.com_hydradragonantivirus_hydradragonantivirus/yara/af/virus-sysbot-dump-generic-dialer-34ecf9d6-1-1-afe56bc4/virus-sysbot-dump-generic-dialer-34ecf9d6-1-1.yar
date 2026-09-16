rule Virus_Sysbot_Dump_Generic_Dialer_34ECF9D6_1_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.34ECF9D6_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "54ec93e202394d9dbaf88c19289193ee046dd2566ee1deef620ba3bbbfb8c8ca"

  strings:
    $s1 = "4|*BREI" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}