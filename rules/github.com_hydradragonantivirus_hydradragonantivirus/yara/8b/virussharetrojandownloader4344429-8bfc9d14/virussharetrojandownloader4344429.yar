rule VirusShareTrojanDownLoader4344429 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanDownLoader4344429.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02c3bf8b4de039820398d955e6433d2aae46fa6d10ad1dbe56786bb4399f6585"

  strings:
    $s1 = "WILE!@~" fullword ascii
    $s2 = "wERE)A" fullword ascii
    $s3 = "NONe; " fullword ascii
    $s4 = " <JUrE" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}