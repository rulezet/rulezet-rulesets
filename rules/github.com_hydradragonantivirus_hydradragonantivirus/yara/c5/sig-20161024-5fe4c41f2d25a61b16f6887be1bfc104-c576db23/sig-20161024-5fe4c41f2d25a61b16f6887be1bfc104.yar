rule sig_20161024_5fe4c41f2d25a61b16f6887be1bfc104 {
  meta:
    description = "datamaliciousorder - file 20161024_5fe4c41f2d25a61b16f6887be1bfc104.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "698b970a706a2a7ed49346e389ac003b41a68a4fcfb76c04d421a750fb96e9ff"

  strings:
    $s1 = "} while (qp++ < zz);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}