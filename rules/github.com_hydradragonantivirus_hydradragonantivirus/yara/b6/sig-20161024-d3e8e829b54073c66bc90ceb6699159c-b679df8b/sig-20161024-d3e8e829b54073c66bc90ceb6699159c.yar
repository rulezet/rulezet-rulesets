rule sig_20161024_d3e8e829b54073c66bc90ceb6699159c {
  meta:
    description = "datamaliciousorder - file 20161024_d3e8e829b54073c66bc90ceb6699159c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "435495f07eacb27f982af5798136dafb9a17aad44c6aba7486caaf61213bcff4"

  strings:
    $s1 = "} while (fj++ < rw);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}