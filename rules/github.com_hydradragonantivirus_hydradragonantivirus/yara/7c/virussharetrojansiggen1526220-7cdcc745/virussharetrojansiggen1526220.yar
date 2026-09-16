rule VirusShareTrojanSiggen1526220 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanSiggen1526220.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ef21cd6341fb6e63ce7be972224f6bb9f51164d86f6b81e93eaf734720ae4f0c"

  strings:
    $s1 = ")WriT!" fullword ascii
    $s2 = "Naos)K'" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}