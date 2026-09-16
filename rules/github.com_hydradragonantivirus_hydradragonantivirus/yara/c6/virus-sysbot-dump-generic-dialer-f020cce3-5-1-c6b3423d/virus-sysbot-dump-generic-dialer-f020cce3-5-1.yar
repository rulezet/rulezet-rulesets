rule Virus_Sysbot_Dump_Generic_Dialer_F020CCE3_5_1 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.F020CCE3_5_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fbfd8a8326b52504af2e42a9b2ab777f571c1089cda32bf1b18e724b8f871f53"

  strings:
    $s1 = "aLiKe$VE" fullword ascii
    $s2 = "SAFt{6" fullword ascii
    $s3 = "DaZy*<" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}