rule sig_20161024_d7e98f5f387fbd25e801ddb86ec653df {
  meta:
    description = "datamaliciousorder - file 20161024_d7e98f5f387fbd25e801ddb86ec653df.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ece7cbe8027d302b4e169718a0a8a706cb52496ac52b41e97fd5dcce6b3fc10e"

  strings:
    $s1 = "} while (al++ < sa);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}