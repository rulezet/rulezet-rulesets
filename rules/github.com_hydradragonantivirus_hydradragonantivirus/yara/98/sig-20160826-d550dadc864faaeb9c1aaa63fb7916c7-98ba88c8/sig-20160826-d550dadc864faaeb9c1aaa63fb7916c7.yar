rule sig_20160826_d550dadc864faaeb9c1aaa63fb7916c7 {
  meta:
    description = "datamaliciousorder - file 20160826_d550dadc864faaeb9c1aaa63fb7916c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aee52a2889c1e3a1854fafd6cb47c15103f813d6a72161f50735200a4e63645a"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x58\",\"\\x51\",\"\\x73\",\"\\x3d\",\"\\x22\",\"\\x63" ascii
    $s2 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x58\",\"\\x51\",\"\\x73\",\"\\x3d\",\"\\x22\",\"\\x63" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}