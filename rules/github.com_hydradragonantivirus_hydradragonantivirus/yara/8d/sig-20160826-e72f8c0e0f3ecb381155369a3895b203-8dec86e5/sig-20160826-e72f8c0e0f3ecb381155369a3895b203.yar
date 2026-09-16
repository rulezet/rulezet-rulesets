rule sig_20160826_e72f8c0e0f3ecb381155369a3895b203 {
  meta:
    description = "datamaliciousorder - file 20160826_e72f8c0e0f3ecb381155369a3895b203.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a7a0746a1297ddb259d73ccb7f0be8b3f7c04d579a625af3d8204d993d951ad3"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"\\x6a\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}