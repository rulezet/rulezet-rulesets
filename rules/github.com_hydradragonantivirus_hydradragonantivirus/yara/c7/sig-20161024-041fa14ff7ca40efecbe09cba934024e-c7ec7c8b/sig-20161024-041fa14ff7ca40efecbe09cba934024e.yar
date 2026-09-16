rule sig_20161024_041fa14ff7ca40efecbe09cba934024e {
  meta:
    description = "datamaliciousorder - file 20161024_041fa14ff7ca40efecbe09cba934024e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06a1b10e003df01bbb33b97d3a1e0cc4d792fecbff762db13ffa3f3d6cd8b5d9"

  strings:
    $s1 = "} while (bh++ < nf0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}