rule sig_20161024_f61e1e3740b2b7eebad07d1c4ca81337 {
  meta:
    description = "datamaliciousorder - file 20161024_f61e1e3740b2b7eebad07d1c4ca81337.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "640f9fb4eeb02b0ec0ee11f1ab2f81f9ae93eca3628d39ada5a8c9242156239b"

  strings:
    $s1 = "} while (yx++ < px);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}