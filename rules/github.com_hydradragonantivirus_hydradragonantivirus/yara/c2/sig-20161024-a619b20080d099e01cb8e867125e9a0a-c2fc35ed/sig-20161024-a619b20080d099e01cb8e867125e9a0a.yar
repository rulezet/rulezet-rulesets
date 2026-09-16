rule sig_20161024_a619b20080d099e01cb8e867125e9a0a {
  meta:
    description = "datamaliciousorder - file 20161024_a619b20080d099e01cb8e867125e9a0a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "914d609c1541e3c8f9289c448353129d2a10898e85828fac3b77374fcc6cd097"

  strings:
    $s1 = "} while (xu0++ < ud0);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}