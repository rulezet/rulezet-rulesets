rule sig_20161024_539b3aca9a8a7e82e0aa4f83011213a4 {
  meta:
    description = "datamaliciousorder - file 20161024_539b3aca9a8a7e82e0aa4f83011213a4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "06184a7fdb3dacdeb3cea10d0fa9c37a9aff2b0ccd0fbdb91ceefded992fb819"

  strings:
    $s1 = "} while (hk++ < qe);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}