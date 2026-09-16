rule sig_20160826_042302204c290e1fd190ee26959a1758 {
  meta:
    description = "datamaliciousorder - file 20160826_042302204c290e1fd190ee26959a1758.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3d4154e7132c4c2aa8b0648fe176f7447d7a08f2ea3c5f3a17eacdb86874f8fa"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4d\",\"\\x6c\",\"\\x3d\",\"\\x22\",\"\\x65\",\"\\x2b" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}