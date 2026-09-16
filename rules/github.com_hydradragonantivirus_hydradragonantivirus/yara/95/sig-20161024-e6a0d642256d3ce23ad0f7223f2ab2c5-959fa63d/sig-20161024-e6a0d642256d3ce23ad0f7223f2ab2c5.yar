rule sig_20161024_e6a0d642256d3ce23ad0f7223f2ab2c5 {
  meta:
    description = "datamaliciousorder - file 20161024_e6a0d642256d3ce23ad0f7223f2ab2c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ea74d10c00dcc0a5960d5f1a3f81efec6c06b1b9f80c83d073daa8030b748d72"

  strings:
    $s1 = "} while (pk++ < oz);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}