rule sig_20161024_a32cd8004665a2e36d2ccb57d2bf9896 {
  meta:
    description = "datamaliciousorder - file 20161024_a32cd8004665a2e36d2ccb57d2bf9896.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f4dc06ecda0ea13aceeab033a90906a51f411ef0b70d01566faaf1a1764c8859"

  strings:
    $s1 = "} while (iw++ < ta);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}