rule sig_20161024_be1c959148bf7a13e2028eb00322a9c6 {
  meta:
    description = "datamaliciousorder - file 20161024_be1c959148bf7a13e2028eb00322a9c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e90d4d41101f00f6e8d18801db5af7b47b2d8f1960ca1e30990b8ea22c29130a"

  strings:
    $s1 = "} while (fj++ < rw0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}