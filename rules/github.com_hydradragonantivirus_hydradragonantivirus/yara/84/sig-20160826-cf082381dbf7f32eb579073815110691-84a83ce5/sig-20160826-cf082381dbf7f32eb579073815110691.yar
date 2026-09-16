rule sig_20160826_cf082381dbf7f32eb579073815110691 {
  meta:
    description = "datamaliciousorder - file 20160826_cf082381dbf7f32eb579073815110691.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bff04e37d64715194c88d905688849e5dccc2677c2463b35f50317b307e344ae"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4d\",\"\\x6c\",\"\\x3d\",\"\\x22\",\"\\x65\",\"\\x2b" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}