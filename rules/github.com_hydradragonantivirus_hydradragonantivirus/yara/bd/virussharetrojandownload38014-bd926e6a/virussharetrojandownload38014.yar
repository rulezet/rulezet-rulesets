rule VirusShareTrojanDownLoad38014 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoad38014.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17673d5d3b3c49641db02c4cd2dcf052ec18585b66e13817374054fcdcf03e5d"

  strings:
    $s1 = "soft Visual" fullword ascii
    $s2 = "Run>Delay" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}