rule sig_20161024_5a1d0fc84285f7fdf46f2eebf1a49075 {
  meta:
    description = "datamaliciousorder - file 20161024_5a1d0fc84285f7fdf46f2eebf1a49075.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a11742b2e623da8980e75e66ab079822e569da41e60068dbeaf93c27a85c5b25"

  strings:
    $s1 = "} while (cb++ < op);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}