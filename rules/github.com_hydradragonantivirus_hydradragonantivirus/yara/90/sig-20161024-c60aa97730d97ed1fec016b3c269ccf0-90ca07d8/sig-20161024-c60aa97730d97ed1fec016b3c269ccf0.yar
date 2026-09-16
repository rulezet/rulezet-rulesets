rule sig_20161024_c60aa97730d97ed1fec016b3c269ccf0 {
  meta:
    description = "datamaliciousorder - file 20161024_c60aa97730d97ed1fec016b3c269ccf0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "206da9e1e90da696f9a8fbc46975434786801dccc5e18e6ee6b244e5b55a12b8"

  strings:
    $s1 = "} while (xq0++ < kh);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}