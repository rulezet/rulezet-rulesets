rule sig_20161024_5723383822ed08acdb08f72dd657aba8 {
  meta:
    description = "datamaliciousorder - file 20161024_5723383822ed08acdb08f72dd657aba8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32ab622595993e7457b4eb86910d97373bee542ce89ce9a9774a3a80b0bf5b11"

  strings:
    $s1 = "} while (ov++ < tf);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}