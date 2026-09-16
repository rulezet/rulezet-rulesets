rule sig_20160826_ef4bfb8dd90000c12f52a8899342af42 {
  meta:
    description = "datamaliciousorder - file 20160826_ef4bfb8dd90000c12f52a8899342af42.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f561ca820b25e3ca34e0be8036e5ee9f981086cfe8e5125e2def99d3c759e166"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x46\",\"\\x64\",\"0\",\"\\x3d\",\"\\x22\",\"\\x65\"," ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}