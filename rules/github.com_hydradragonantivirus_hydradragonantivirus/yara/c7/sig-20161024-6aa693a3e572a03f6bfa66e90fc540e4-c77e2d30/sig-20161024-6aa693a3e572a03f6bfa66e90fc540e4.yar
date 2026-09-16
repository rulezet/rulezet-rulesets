rule sig_20161024_6aa693a3e572a03f6bfa66e90fc540e4 {
  meta:
    description = "datamaliciousorder - file 20161024_6aa693a3e572a03f6bfa66e90fc540e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1841f43a00beed04a055ca727cd3c4c767f78cc803392de39c60dc50772c3be3"

  strings:
    $s1 = "} while (og++ < xd);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}