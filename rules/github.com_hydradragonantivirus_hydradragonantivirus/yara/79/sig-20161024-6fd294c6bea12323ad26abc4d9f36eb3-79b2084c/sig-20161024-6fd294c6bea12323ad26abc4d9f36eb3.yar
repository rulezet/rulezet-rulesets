rule sig_20161024_6fd294c6bea12323ad26abc4d9f36eb3 {
  meta:
    description = "datamaliciousorder - file 20161024_6fd294c6bea12323ad26abc4d9f36eb3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "357b35b7138986073499909fa32d8fe23ee175b259a6ce9c21b119202a782fc1"

  strings:
    $s1 = "} while (na++ < nr);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}