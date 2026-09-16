rule Virus_Hijack_Trojan_GenericKDZ_98113_416_1 {
  meta:
    description = "datamaliciousorder - file Virus.Hijack_Trojan.GenericKDZ.98113_416_1.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "efaab181870c57e37aca14e1d5b78e4070ed9023488ad84e5814f3c8d7884134"

  strings:
    $s1 = ")ogle%l" fullword ascii
    $s2 = "'\"wIRe" fullword ascii
    $s3 = "MoxA#~" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}