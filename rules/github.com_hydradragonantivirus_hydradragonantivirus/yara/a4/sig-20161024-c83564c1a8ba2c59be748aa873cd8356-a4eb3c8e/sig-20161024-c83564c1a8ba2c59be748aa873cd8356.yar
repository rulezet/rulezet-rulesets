rule sig_20161024_c83564c1a8ba2c59be748aa873cd8356 {
  meta:
    description = "datamaliciousorder - file 20161024_c83564c1a8ba2c59be748aa873cd8356.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6e4945852ae504d3fc5e448e77191227adaee8308c364933b3d371fa81487972"

  strings:
    $s1 = "} while (nn++ < gy0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}