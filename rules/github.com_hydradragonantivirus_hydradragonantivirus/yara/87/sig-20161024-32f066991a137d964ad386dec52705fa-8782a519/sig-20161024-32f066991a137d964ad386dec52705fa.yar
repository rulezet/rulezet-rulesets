rule sig_20161024_32f066991a137d964ad386dec52705fa {
  meta:
    description = "datamaliciousorder - file 20161024_32f066991a137d964ad386dec52705fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e20cf87fc11653dd3480633fb41c7982f44beacfa785d15988dc9242d2cde8b7"

  strings:
    $s1 = "} while (wc1++ < rk);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}