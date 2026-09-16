rule sig_20161024_377d2d232cef63c5636410190a781477 {
  meta:
    description = "datamaliciousorder - file 20161024_377d2d232cef63c5636410190a781477.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "239bb01839d3b9a90f9a5712d51560ad5ea56e55a354d2b11bc6e77be8469bd3"

  strings:
    $s1 = "} while (za++ < cy);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}