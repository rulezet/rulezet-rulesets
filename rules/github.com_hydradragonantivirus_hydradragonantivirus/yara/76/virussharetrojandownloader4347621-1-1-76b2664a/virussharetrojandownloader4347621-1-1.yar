rule VirusShareTrojanDownLoader4347621_1_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader4347621_1_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6d90a9ba6a2113da09096a2a4e9664e39202f4e3c728ab503de22e0396b6dc42"

  strings:
    $s1 = "Tepidly" fullword ascii
    $s2 = "Botanist" fullword ascii
    $s3 = "Homoblasty Dismissed Inc.1" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}