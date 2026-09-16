rule sig_20160523_883c550afa44bf137d6643d4c2f6956f {
  meta:
    description = "datamaliciousorder - file 20160523_883c550afa44bf137d6643d4c2f6956f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e751aa4144e19dcdc890be151b5f5ea2388117ece8ec40cd16d380f5ad9b5aab"

  strings:
    $s1 = "join('');" fullword ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}