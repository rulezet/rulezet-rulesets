rule sig_20161024_b51cbda95c17825c5607fa8ddf7b96c1 {
  meta:
    description = "datamaliciousorder - file 20161024_b51cbda95c17825c5607fa8ddf7b96c1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "17594e6c847e59fc5f646a6575e31d00ea3cc91eb79010eb340b824be4af951c"

  strings:
    $s1 = "} while (zd++ < ml);" fullword ascii

  condition:
    uint16(0) == 0x0a0a and
    all of them
}