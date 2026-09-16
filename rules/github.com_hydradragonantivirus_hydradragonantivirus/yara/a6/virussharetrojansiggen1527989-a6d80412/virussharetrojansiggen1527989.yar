rule VirusShareTrojanSiggen1527989 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1527989.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d3c967ebe05bcd11c84a933670ecdc748a621ab5b3892c45c883c0d55ba556f3"

  strings:
    $s1 = "%tALD%" fullword ascii
    $s2 = "Ricin Ullaging Inc.1" fullword ascii
    $s3 = "hUla?u" fullword ascii
    $s4 = "s prog" fullword ascii
    $s5 = ")]oveR" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}