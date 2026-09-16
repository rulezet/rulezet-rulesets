rule sig_20161024_88a6f651b35b4216c1939a1f1898f65c {
  meta:
    description = "datamaliciousorder - file 20161024_88a6f651b35b4216c1939a1f1898f65c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "169c912227c4ee030e2057b7efcfedc752070cd09e33a5bfa30b068fea309697"

  strings:
    $s1 = "} while (wi0++ < ii);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}