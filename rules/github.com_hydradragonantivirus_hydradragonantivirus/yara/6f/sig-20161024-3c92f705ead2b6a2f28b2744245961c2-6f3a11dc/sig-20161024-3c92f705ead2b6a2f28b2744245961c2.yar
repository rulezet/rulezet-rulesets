rule sig_20161024_3c92f705ead2b6a2f28b2744245961c2 {
  meta:
    description = "datamaliciousorder - file 20161024_3c92f705ead2b6a2f28b2744245961c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bede0bc2d5174c4c1e26aae04075f6e9ff6e1bc13ee7b0e3bd078e12d4f3db4d"

  strings:
    $s1 = "} while (ta++ < hp);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}