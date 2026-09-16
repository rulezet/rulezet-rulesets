rule VirusShareTrojanDownLoader4344060_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader4344060_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3db28cb0c018f2daeabb18559b3e436d477221bc242e4a193b82cc938a04c35"

  strings:
    $s1 = "+*!hUrT<+CR]" fullword ascii
    $s2 = "Virtual CD/DVD Manager" fullword wide

  condition:
    uint16(0) == 0x5a4d and
    all of them
}