rule sig_20160826_3f9ed96f31a75741854e58fd22981751 {
  meta:
    description = "datamaliciousorder - file 20160826_3f9ed96f31a75741854e58fd22981751.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e0828c4427605e392de8eca8723e923f81a9eed6a47d949236d1586f9acfeef"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"\\x6a\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}