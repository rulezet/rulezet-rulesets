rule Virus_Sysbot_Dump_Generic_Dialer_5485D7ED_11 {
  meta:
    description = "datamaliciousorder - file Virus.Sysbot_Dump.Generic.Dialer.5485D7ED_11.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc316d09801e0b14fa6d3a058a7847e88753b32666d31e4a17669e28c26dfdf3"

  strings:
    $s1 = "PeeD$3" fullword ascii
    $s2 = "gleN)>" fullword ascii
    $s3 = "!}helm" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}