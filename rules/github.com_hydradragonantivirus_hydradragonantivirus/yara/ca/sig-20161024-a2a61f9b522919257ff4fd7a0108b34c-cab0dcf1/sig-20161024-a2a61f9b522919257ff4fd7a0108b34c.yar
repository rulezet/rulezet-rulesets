rule sig_20161024_a2a61f9b522919257ff4fd7a0108b34c {
  meta:
    description = "datamaliciousorder - file 20161024_a2a61f9b522919257ff4fd7a0108b34c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d45e2cd5eefcb542e7c05094d9dc9dd628afb9fb26442d079cfc99f503bfa96c"

  strings:
    $s1 = "} while (bp++ < vu);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}