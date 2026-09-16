rule sig_20161024_7e4d73b3de6f7de32223e522d0da039c {
  meta:
    description = "datamaliciousorder - file 20161024_7e4d73b3de6f7de32223e522d0da039c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f5eb79be62a92812975ceef7e10317a03cdeba8605db709ff28f3635faef6ca6"

  strings:
    $s1 = "} while (yp++ < gp);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}