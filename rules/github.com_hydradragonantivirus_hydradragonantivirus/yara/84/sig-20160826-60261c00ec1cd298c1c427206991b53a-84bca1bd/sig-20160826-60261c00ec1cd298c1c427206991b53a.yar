rule sig_20160826_60261c00ec1cd298c1c427206991b53a {
  meta:
    description = "datamaliciousorder - file 20160826_60261c00ec1cd298c1c427206991b53a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d6baafc2b1546c11feb4af335bb9587ab248620f37ae74ad5dbcba1802525900"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x58\",\"\\x51\",\"\\x73\",\"\\x3d\",\"\\x22\",\"\\x63" ascii
    $s2 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x58\",\"\\x51\",\"\\x73\",\"\\x3d\",\"\\x22\",\"\\x63" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}