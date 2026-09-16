rule sig_20161024_52309ad44f0e52183a85ad3a2800a557 {
  meta:
    description = "datamaliciousorder - file 20161024_52309ad44f0e52183a85ad3a2800a557.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "79b4feb25acd297d909b3c285d9bcb9fbe6ae24aa43762a99d83c9b060c4dc5c"

  strings:
    $s1 = "} while (gj++ < eg);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}