rule sig_20161024_9ee406f31bdcb9b20ad16bd8a7d2073f {
  meta:
    description = "datamaliciousorder - file 20161024_9ee406f31bdcb9b20ad16bd8a7d2073f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b90be804ca772e69a3342f80d84c619059e6cd71d7b90fcc48f3e4f7122e10e"

  strings:
    $s1 = "} while (oi++ < xf);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}