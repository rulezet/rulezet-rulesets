rule sig_20161024_49f39ec1ca90f501bb7df9d915c6acc6 {
  meta:
    description = "datamaliciousorder - file 20161024_49f39ec1ca90f501bb7df9d915c6acc6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e5115064fcd15ba98e7949986cc2e767a9a338d20d73dde2ca9e420fb80f3f27"

  strings:
    $s1 = "} while (yk0++ < eq0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}