rule sig_20160826_4a5fda61985392a36a339a8c2d0f9635 {
  meta:
    description = "datamaliciousorder - file 20160826_4a5fda61985392a36a339a8c2d0f9635.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e2f126f4ebc7777e855bfa0deb0e436c923e51bdb8090f949fc84a2ad6a45ca9"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"3\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65\"," ascii
    $s2 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"3\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65\"," ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}