rule sig_20161024_327cbd24a58ab290b0c7908b301be207 {
  meta:
    description = "datamaliciousorder - file 20161024_327cbd24a58ab290b0c7908b301be207.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "44e1fb55d09b90e029efb8df499824d4e66d7fd6d457635e981019374ec96cf5"

  strings:
    $s1 = "} while (tp++ < pc);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}