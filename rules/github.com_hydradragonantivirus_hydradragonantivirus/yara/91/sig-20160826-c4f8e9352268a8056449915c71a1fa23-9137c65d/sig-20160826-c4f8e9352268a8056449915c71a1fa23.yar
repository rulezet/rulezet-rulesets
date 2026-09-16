rule sig_20160826_c4f8e9352268a8056449915c71a1fa23 {
  meta:
    description = "datamaliciousorder - file 20160826_c4f8e9352268a8056449915c71a1fa23.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0297dab98ca5aac3161aa8a4e78147514ea16242c7a7d2a208c2df4d603c66b8"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x46\",\"\\x64\",\"0\",\"\\x3d\",\"\\x22\",\"\\x65\"," ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}