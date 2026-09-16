rule VirusShareTrojanSiggen817711_1 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen817711_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27e169097ddb46a4972ecb6a67fad0cbd0c992873eb0c7bdf7015f5b08f7d16a"

  strings:
    $s1 = "Screen Spy " fullword ascii
    $s2 = "FastMM Borland Edition ?2004, 2005 Pierre le Riche / Professional Software Development" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}