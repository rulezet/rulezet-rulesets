rule sig_20161024_eaf5f3bdd559e40d596bd3674a317c3a {
  meta:
    description = "datamaliciousorder - file 20161024_eaf5f3bdd559e40d596bd3674a317c3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "abbaa66fe0558c676c54403cab0d0cdfc84cb772cd81f554990c8c6e7610264a"

  strings:
    $s1 = "} while (ad++ < rh);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}