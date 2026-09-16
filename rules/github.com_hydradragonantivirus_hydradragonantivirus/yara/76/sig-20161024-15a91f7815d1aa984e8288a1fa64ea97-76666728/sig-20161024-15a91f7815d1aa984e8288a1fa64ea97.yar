rule sig_20161024_15a91f7815d1aa984e8288a1fa64ea97 {
  meta:
    description = "datamaliciousorder - file 20161024_15a91f7815d1aa984e8288a1fa64ea97.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6279619c3c6c58e26301a7708df1e6cb5ebce381df7364c5c6d43d9e34c93acb"

  strings:
    $s1 = "} while (sy++ < zt);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}