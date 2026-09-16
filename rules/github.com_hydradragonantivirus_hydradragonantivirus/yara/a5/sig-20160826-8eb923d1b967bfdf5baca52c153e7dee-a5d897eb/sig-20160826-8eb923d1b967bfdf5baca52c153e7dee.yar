rule sig_20160826_8eb923d1b967bfdf5baca52c153e7dee {
  meta:
    description = "datamaliciousorder - file 20160826_8eb923d1b967bfdf5baca52c153e7dee.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b864cb7e00b4e47965cc959a989f8c9d7e9f6cba07ffc47608b0196dc02f184"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x58\",\"\\x51\",\"\\x73\",\"\\x3d\",\"\\x22\",\"\\x63" ascii
    $s2 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x58\",\"\\x51\",\"\\x73\",\"\\x3d\",\"\\x22\",\"\\x63" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}