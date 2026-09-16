rule sig_20161007_d367f9357defd13460e3d7cda57483b7 {
  meta:
    description = "datamaliciousorder - file 20161007_d367f9357defd13460e3d7cda57483b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b544dc775f85f8bf03d81b23e0e11bce2a401d1e5fe24edd6e7b787348218b54"

  strings:
    $s1 = "} while (dl++ < ow);" fullword ascii

  condition:
    uint16(0) == 0x2f0a and
    all of them
}