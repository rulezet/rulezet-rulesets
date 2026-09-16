rule sig_20161024_5885b1969aef9bbcc9509f13b20660d3 {
  meta:
    description = "datamaliciousorder - file 20161024_5885b1969aef9bbcc9509f13b20660d3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d4200d3ce9e76998b5d4c5159577dc77f5e70e2ac89648cdb611b74caf727feb"

  strings:
    $s1 = "} while (dm++ < un1);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}