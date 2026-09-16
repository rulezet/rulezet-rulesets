rule sig_20161024_6d520394db1729332317fac26f58f0dc {
  meta:
    description = "datamaliciousorder - file 20161024_6d520394db1729332317fac26f58f0dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6774dccb1e4b7deb7a74eb14372bc53cd558739a200eb4c79a614beacca2c185"

  strings:
    $s1 = "} while (lu++ < bf);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}