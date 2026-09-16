rule sig_20161024_19e6c21659611f77a4f4c5dbe3c715bc {
  meta:
    description = "datamaliciousorder - file 20161024_19e6c21659611f77a4f4c5dbe3c715bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "194b2b50fd50c4fd40b49e4ac015073690f7bdffb62a28d0aa997ab5d1d33a59"

  strings:
    $s1 = "} while (ku++ < ya);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}