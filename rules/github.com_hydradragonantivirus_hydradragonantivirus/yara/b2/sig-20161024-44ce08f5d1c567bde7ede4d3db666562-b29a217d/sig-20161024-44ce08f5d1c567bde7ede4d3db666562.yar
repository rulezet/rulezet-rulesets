rule sig_20161024_44ce08f5d1c567bde7ede4d3db666562 {
  meta:
    description = "datamaliciousorder - file 20161024_44ce08f5d1c567bde7ede4d3db666562.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3dc1e74982f62b0961b012f796c049e1cea8b3d8ae12cc5a4722aa703c8ed356"

  strings:
    $s1 = "} while (ri0++ < zz);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}