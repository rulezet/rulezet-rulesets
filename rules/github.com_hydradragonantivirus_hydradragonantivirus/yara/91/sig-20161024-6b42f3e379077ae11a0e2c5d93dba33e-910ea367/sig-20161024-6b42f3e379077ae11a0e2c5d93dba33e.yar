rule sig_20161024_6b42f3e379077ae11a0e2c5d93dba33e {
  meta:
    description = "datamaliciousorder - file 20161024_6b42f3e379077ae11a0e2c5d93dba33e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cd13c849ef212c525967eb36f10de43a0e86974d66eb5ddf20881020169af4fa"

  strings:
    $s1 = "} while (vr0++ < zt);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}