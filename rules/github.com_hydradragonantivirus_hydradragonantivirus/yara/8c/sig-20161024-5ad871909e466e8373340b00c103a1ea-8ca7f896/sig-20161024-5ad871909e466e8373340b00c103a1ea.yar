rule sig_20161024_5ad871909e466e8373340b00c103a1ea {
  meta:
    description = "datamaliciousorder - file 20161024_5ad871909e466e8373340b00c103a1ea.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a669f4a4568fec7e7e26508e24081f2af44f0b28ac03f8c2d9d8261f3ec60e5"

  strings:
    $s1 = "} while (to++ < ym);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}