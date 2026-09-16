rule sig_20161024_4489c1cfb41153e96521fbda7d2fe7a1 {
  meta:
    description = "datamaliciousorder - file 20161024_4489c1cfb41153e96521fbda7d2fe7a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "40864bd6a788a8843e36ba08d60f0613ce2db23076a5b1db54f8373420da0a05"

  strings:
    $s1 = "} while (mi++ < se);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}