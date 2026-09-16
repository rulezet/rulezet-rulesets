rule sig_20161024_aaa60a913828d5f68ae8accc6a5edfb1 {
  meta:
    description = "datamaliciousorder - file 20161024_aaa60a913828d5f68ae8accc6a5edfb1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9971ad2afac013a7c326805d0d0713992b81dbf6bc171f3096afc2830365946"

  strings:
    $s1 = "} while (xc++ < dj);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}