rule sig_20161024_9e69f585dec1e7bac752ef13cee8aa26 {
  meta:
    description = "datamaliciousorder - file 20161024_9e69f585dec1e7bac752ef13cee8aa26.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "02aa46cd9e367e3ba87e906adbade4c90fdfe37f0a23717a245805397ce0a404"

  strings:
    $s1 = "} while (aq++ < we);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}