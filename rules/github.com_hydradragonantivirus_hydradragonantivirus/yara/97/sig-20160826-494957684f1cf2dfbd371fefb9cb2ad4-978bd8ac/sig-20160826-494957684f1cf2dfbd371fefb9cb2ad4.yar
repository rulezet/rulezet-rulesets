rule sig_20160826_494957684f1cf2dfbd371fefb9cb2ad4 {
  meta:
    description = "datamaliciousorder - file 20160826_494957684f1cf2dfbd371fefb9cb2ad4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "63e6d824f37e7e656d4281dec91277ad962b12b49c843fbf20f38f363485b84f"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4d\",\"\\x6c\",\"\\x3d\",\"\\x22\",\"\\x65\",\"\\x2b" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}