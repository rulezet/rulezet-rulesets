rule Virus_Sysbot_Dump_Generic_Dialer_BC6FFEAD_16_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BC6FFEAD_16_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6bb3bc40e6caaf7687764a37c5daa74641d7dbcec5b28b59614649439a760ca3"

  strings:
    $s1 = "ZV!IcHo" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}