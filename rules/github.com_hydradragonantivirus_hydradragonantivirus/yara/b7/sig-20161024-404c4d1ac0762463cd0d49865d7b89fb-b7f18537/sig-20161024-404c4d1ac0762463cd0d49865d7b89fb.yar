rule sig_20161024_404c4d1ac0762463cd0d49865d7b89fb {
  meta:
    description = "datamaliciousorder - file 20161024_404c4d1ac0762463cd0d49865d7b89fb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bf8ee2d3a44d644af45b00bec0b3942a0c5ae2e49e7b7a05ac522fc98f724deb"

  strings:
    $s1 = "} while (ql++ < jt);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}