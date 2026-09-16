rule sig_20161024_efaef0d4a864fc47a9e91a11096d57b8 {
  meta:
    description = "datamaliciousorder - file 20161024_efaef0d4a864fc47a9e91a11096d57b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e858d873976c0eb1e958974585a140981d5d062e7003d079c7c5e2ab05c69b3c"

  strings:
    $s1 = "} while (sq++ < ha);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}