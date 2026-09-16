rule VirusShareTrojanSiggen533512 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen533512.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7b3d63869efe8662957417ec9f9dd9ae6501c8bd748a86709c9d830fe399101"

  strings:
    $s1 = "inner message" fullword ascii
    $s2 = "!Share" fullword ascii
    $s3 = "Can not create DIB section, error: " fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}