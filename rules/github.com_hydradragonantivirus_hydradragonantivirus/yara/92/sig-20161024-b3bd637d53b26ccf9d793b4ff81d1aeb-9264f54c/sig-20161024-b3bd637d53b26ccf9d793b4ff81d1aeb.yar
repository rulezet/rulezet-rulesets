rule sig_20161024_b3bd637d53b26ccf9d793b4ff81d1aeb {
  meta:
    description = "datamaliciousorder - file 20161024_b3bd637d53b26ccf9d793b4ff81d1aeb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3d0ffbea09961c98ff0a41b05634ddc75c9c409da38b3eeeff88c80ff90be05"

  strings:
    $s1 = "} while (jn++ < nh);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}