rule sig_20161024_b76572a3ec1adda17dbc60a6ac4a0eda {
  meta:
    description = "datamaliciousorder - file 20161024_b76572a3ec1adda17dbc60a6ac4a0eda.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "58a9dc685e8c1be407334a79f1a0680d3764b0061de154e68cc7afc67ec7153f"

  strings:
    $s1 = "} while (xk++ < fu);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}