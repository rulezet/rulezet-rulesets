rule sig_20161024_4f7589948cee2c73ebf9dc9cb37e9948 {
  meta:
    description = "datamaliciousorder - file 20161024_4f7589948cee2c73ebf9dc9cb37e9948.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "305ecf657720da16716cac14c6fba829ae2ae9be15a56ee7763484c796c7ff9c"

  strings:
    $s1 = "} while (hw++ < ey);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}