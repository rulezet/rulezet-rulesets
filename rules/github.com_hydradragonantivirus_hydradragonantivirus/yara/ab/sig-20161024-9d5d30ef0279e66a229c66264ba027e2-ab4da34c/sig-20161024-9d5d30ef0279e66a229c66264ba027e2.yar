rule sig_20161024_9d5d30ef0279e66a229c66264ba027e2 {
  meta:
    description = "datamaliciousorder - file 20161024_9d5d30ef0279e66a229c66264ba027e2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b32faee464248e2ba23e080720c35b21bf70f0762c85689b6de46473a55a200b"

  strings:
    $s1 = "} while (ss++ < rz);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}