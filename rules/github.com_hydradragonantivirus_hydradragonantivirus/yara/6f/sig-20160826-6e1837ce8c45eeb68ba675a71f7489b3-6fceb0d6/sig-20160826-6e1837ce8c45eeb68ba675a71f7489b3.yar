rule sig_20160826_6e1837ce8c45eeb68ba675a71f7489b3 {
  meta:
    description = "datamaliciousorder - file 20160826_6e1837ce8c45eeb68ba675a71f7489b3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "12010e482cbab860d29ce3cc3304e6d10b8ea1301cd3bc32860d2b9644842a83"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"\\x6a\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}