rule VirusShareTrojanDownLoader4344001 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader4344001.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2f68014c2f418e8a27d023f7a4a51ee4b3b1f862a5020f648a1b16a6c032e724"

  strings:
    $s1 = "mAnA{4d" fullword ascii
    $s2 = "!%MeSa" fullword ascii
    $s3 = "^ :fiLO" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}