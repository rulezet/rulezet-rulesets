rule VirusShareTrojanDownLoader2352349 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader2352349.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd7d41450ffc7079b2161a20d02c5682e1a5eddf75b6fa1f31193f8067d20750"

  strings:
    $s1 = "#Powered by SmartAssembly 6.12.1.641" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}