rule sig_20161024_78b562b4b4f8ce3f2bf5e15689c984d0 {
  meta:
    description = "datamaliciousorder - file 20161024_78b562b4b4f8ce3f2bf5e15689c984d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "32e4912f3d3c87b4d23e8468763fe133883f81770fce56bb0c6fab37dae02c3c"

  strings:
    $s1 = "} while (jn++ < nh0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}