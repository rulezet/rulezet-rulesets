rule sig_20161024_dc9178a940f7d12c7fbf347b3bf018ab {
  meta:
    description = "datamaliciousorder - file 20161024_dc9178a940f7d12c7fbf347b3bf018ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c93588253e2623d00945ab21717db48851674c9863e04eb9640c8fdda84c2d82"

  strings:
    $s1 = "} while (jd++ < zd);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}