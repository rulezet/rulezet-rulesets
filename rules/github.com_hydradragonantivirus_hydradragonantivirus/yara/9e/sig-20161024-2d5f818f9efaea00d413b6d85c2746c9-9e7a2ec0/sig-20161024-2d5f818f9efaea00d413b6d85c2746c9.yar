rule sig_20161024_2d5f818f9efaea00d413b6d85c2746c9 {
  meta:
    description = "datamaliciousorder - file 20161024_2d5f818f9efaea00d413b6d85c2746c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f60a279a7ec0e3e48648fd055e7963b7a87c3d200957b4fa21a775f13de2aece"

  strings:
    $s1 = "} while (xj++ < cy);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}