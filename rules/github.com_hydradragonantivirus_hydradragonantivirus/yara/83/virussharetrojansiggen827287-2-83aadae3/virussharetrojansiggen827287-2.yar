rule VirusShareTrojanSiggen827287_2 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen827287_2.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "60e37ac0984f8d7addfd3e6175545aa235aa1b2f559ba172570d6ce5ee60bbfc"

  strings:
    $s1 = "Malware Test File" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}