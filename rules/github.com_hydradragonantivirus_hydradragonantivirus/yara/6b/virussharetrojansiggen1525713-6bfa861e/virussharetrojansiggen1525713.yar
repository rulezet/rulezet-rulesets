rule VirusShareTrojanSiggen1525713 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1525713.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "00cd272476489e41fb7f6a4ccaa0b6e4b922c23033b2dc5bfdb79a13da43a850"

  strings:
    $s1 = "Copy (C) 2006-2022 adaware" fullword wide
    $s2 = "Trade (R) 2006-2022 adaware" fullword wide
    $s3 = "i%gAMy{Y" fullword ascii
    $s4 = "@This p" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}