rule sig_20161024_219671356fbfb298b0140f867b59ce3a {
  meta:
    description = "datamaliciousorder - file 20161024_219671356fbfb298b0140f867b59ce3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a8279640558b1042d11502692755b6c4217362ef52a2bacda78a17234fe2d960"

  strings:
    $s1 = "} while (ln++ < ju);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}