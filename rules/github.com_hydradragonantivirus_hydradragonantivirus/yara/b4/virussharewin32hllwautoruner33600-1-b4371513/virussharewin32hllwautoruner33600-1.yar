rule VirusShareWin32HLLWAutoruner33600_1 {
  meta:
    description = "datamaliciousorder - file VirusShareWin32HLLWAutoruner33600_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8387ad32144c17a6ed8f986d4841d1caa85c54b41a0da7961bc199642a62380d"

  strings:
    $s1 = "5@aRni" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}