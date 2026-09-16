rule sig_20160826_23f86cd368ef3b0aa3956cd5114d1c3c {
  meta:
    description = "datamaliciousorder - file 20160826_23f86cd368ef3b0aa3956cd5114d1c3c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "51e71d6a728d676fab3f04237212408f0cb9fd8ddd487549d9e28eb56ebdc671"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4d\",\"\\x6c\",\"\\x3d\",\"\\x22\",\"\\x65\",\"\\x2b" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}