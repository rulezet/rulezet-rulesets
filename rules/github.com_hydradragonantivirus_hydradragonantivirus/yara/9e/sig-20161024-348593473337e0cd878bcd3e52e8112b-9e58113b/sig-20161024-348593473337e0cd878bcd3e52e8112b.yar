rule sig_20161024_348593473337e0cd878bcd3e52e8112b {
  meta:
    description = "datamaliciousorder - file 20161024_348593473337e0cd878bcd3e52e8112b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "262b4a72ecf164dcba9d36483b31e2f3135ddcfaac7db34a886761432a645749"

  strings:
    $s1 = "} while (xt++ < nl0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}