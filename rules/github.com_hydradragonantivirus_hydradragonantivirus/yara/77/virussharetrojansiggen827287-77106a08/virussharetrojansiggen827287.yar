rule VirusShareTrojanSiggen827287 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen827287.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82de0c833694a3b85ac77e789e6b7dac52786cb8eeb1456db4155f3b6177ef1f"

  strings:
    $s1 = "Malware Test File" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}