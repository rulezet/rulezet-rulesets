rule sig_20161024_0416084af3187e753126926fd2678140 {
  meta:
    description = "datamaliciousorder - file 20161024_0416084af3187e753126926fd2678140.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "330759783c7e127e2173526f1d0ef26478dea8558d6748a98af9d29bc53e14c8"

  strings:
    $s1 = "} while (bu0++ < jw);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}