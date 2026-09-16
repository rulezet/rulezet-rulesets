rule Virus_Sysbot_Dump_Generic_Dialer_BC6FFEAD_4_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.BC6FFEAD_4_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd0cb54121163a640076e93a855d9c81c948ecb72a0b1d40fd35deb043304a47"

  strings:
    $s1 = "Mb?pOLk" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}