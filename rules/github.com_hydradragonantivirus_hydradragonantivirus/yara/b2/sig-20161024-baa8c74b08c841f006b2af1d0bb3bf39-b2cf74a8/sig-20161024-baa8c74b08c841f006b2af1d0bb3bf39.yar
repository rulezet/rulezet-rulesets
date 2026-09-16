rule sig_20161024_baa8c74b08c841f006b2af1d0bb3bf39 {
  meta:
    description = "datamaliciousorder - file 20161024_baa8c74b08c841f006b2af1d0bb3bf39.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7e79bc922b36c03c50c75501e7a06154d5f489f0889071947db790e7980d4964"

  strings:
    $s1 = "} while (rd++ < st);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}