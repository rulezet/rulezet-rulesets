rule sig_20161024_66945552be879674bbcec2f58d55cc47 {
  meta:
    description = "datamaliciousorder - file 20161024_66945552be879674bbcec2f58d55cc47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2c1ad7e31d79ad1c552bcaa8fbdb21c1335bf8916a7ccbece34ae1964ab26e5f"

  strings:
    $s1 = "} while (vt++ < xu);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}