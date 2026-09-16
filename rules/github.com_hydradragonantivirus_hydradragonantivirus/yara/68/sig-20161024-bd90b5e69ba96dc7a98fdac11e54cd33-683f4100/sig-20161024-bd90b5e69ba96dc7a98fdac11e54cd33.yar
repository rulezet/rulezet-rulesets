rule sig_20161024_bd90b5e69ba96dc7a98fdac11e54cd33 {
  meta:
    description = "datamaliciousorder - file 20161024_bd90b5e69ba96dc7a98fdac11e54cd33.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68dccc93bce3f494c4745682a390e5bf67e52a2872dcf363f80cd92d5091a1b6"

  strings:
    $s1 = "} while (sa++ < xo);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}