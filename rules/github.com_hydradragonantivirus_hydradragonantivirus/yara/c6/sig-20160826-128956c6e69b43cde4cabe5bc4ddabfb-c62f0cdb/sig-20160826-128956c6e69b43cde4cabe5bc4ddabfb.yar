rule sig_20160826_128956c6e69b43cde4cabe5bc4ddabfb {
  meta:
    description = "datamaliciousorder - file 20160826_128956c6e69b43cde4cabe5bc4ddabfb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "931b26d3f5e6ad2b799a696a59e9e7583e11d6c9397e3fdae88c2d7a1b4e576e"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x46\",\"\\x64\",\"0\",\"\\x3d\",\"\\x22\",\"\\x65\"," ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}