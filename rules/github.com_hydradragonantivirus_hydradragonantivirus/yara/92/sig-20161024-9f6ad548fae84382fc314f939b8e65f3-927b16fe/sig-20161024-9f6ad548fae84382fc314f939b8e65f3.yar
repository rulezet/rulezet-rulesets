rule sig_20161024_9f6ad548fae84382fc314f939b8e65f3 {
  meta:
    description = "datamaliciousorder - file 20161024_9f6ad548fae84382fc314f939b8e65f3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e7378d8eaaf5f1fe8c51a9c1f7cebe8d95de6df03ae9c43ac626dc187bf8dd7f"

  strings:
    $s1 = "} while (ly++ < mj);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}