rule sig_20160826_b0390e4679d39f833f2944190742dbf9 {
  meta:
    description = "datamaliciousorder - file 20160826_b0390e4679d39f833f2944190742dbf9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed28d6ae4ad7a23fc536a0f125919b8c19388578ccfd589461d98b41dafc0fdc"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x4f\",\"\\x6a\",\"\\x3d\",\"\\x22\",\"\\x73\",\"\\x65" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}