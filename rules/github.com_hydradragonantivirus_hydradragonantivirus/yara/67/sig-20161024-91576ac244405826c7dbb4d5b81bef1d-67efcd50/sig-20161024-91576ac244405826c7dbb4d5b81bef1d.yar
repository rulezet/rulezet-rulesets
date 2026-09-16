rule sig_20161024_91576ac244405826c7dbb4d5b81bef1d {
  meta:
    description = "datamaliciousorder - file 20161024_91576ac244405826c7dbb4d5b81bef1d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "368443305b33922b157521ec1008fd1c664f1c73361f202d3a1643a395e65384"

  strings:
    $s1 = "} while (gi++ < hi);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}