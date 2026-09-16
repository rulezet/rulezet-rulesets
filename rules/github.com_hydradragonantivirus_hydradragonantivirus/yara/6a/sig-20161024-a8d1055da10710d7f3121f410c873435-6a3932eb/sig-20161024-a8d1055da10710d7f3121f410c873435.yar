rule sig_20161024_a8d1055da10710d7f3121f410c873435 {
  meta:
    description = "datamaliciousorder - file 20161024_a8d1055da10710d7f3121f410c873435.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e8c878a43b01e2634723daf6065bc8f4a6e9c3a1c8153f9628bd7e9a1fa0ad4e"

  strings:
    $s1 = "} while (gf++ < xl);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}