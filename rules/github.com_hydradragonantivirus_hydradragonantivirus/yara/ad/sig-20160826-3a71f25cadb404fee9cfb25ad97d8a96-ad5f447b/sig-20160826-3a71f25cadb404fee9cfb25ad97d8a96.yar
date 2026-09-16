rule sig_20160826_3a71f25cadb404fee9cfb25ad97d8a96 {
  meta:
    description = "datamaliciousorder - file 20160826_3a71f25cadb404fee9cfb25ad97d8a96.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a4350bef273ba01cd5241427808fa1c8194de32d285faed82e815e871e3244b"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"3\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65\"," ascii
    $s2 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"3\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65\"," ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}