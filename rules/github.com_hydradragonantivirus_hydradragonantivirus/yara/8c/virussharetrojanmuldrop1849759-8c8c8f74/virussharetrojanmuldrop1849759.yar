rule VirusShareTrojanMulDrop1849759 {
  meta:
    description = "datamaliciousorder - file VirusShareTrojanMulDrop1849759.vir"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c1f9d793b4fba5913c3f46ad608c4861863893865a17c30260074b2b309e143e"

  strings:
    $s1 = "TyPE \"\"%sfXNamE%\"\"" fullword ascii
    $s2 = "  & STarT " fullword ascii
    $s3 = "yUaN>w" fullword ascii

  condition:
    uint16(0) == 0x5a4d and
    all of them
}