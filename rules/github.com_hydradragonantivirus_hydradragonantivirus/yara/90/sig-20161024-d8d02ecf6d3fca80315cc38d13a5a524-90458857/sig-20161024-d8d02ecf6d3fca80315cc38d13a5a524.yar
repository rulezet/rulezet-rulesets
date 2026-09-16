rule sig_20161024_d8d02ecf6d3fca80315cc38d13a5a524 {
  meta:
    description = "datamaliciousorder - file 20161024_d8d02ecf6d3fca80315cc38d13a5a524.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af497af93907038ebe111c18eb941ee82cf32725878061b9e8fdf7ad565ede44"

  strings:
    $s1 = "} while (np++ < eh);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}