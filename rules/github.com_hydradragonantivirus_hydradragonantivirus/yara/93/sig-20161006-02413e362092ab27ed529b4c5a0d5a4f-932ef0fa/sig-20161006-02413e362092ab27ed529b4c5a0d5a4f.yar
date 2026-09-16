rule sig_20161006_02413e362092ab27ed529b4c5a0d5a4f {
  meta:
    description = "datamaliciousorder - file 20161006_02413e362092ab27ed529b4c5a0d5a4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9c56f9fca58cc00d27a66681cdabcd5a356ae5bba14fbc998fb9d05d639a2a0"

  strings:
    $s1 = "} while (dl++ < ow);" fullword ascii

  condition:
    uint16(0) == 0x2f0a and
    all of them
}