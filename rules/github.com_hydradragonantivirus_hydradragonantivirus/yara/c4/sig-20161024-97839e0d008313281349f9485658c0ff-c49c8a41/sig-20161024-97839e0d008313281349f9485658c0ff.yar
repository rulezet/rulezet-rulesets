rule sig_20161024_97839e0d008313281349f9485658c0ff {
  meta:
    description = "datamaliciousorder - file 20161024_97839e0d008313281349f9485658c0ff.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "01dab8b0b847f0c21f14e9428f7cce13ce4ca47fb2b12e278ba0ee466e3e4842"

  strings:
    $s1 = "} while (zx++ < ej);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}