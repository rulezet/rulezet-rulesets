rule sig_20160826_4de813eb82e9c4205043568f0274be09 {
  meta:
    description = "datamaliciousorder - file 20160826_4de813eb82e9c4205043568f0274be09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "af8164c506e5fb678930d0b067823ec10dd241837e5fdca5178ce140ec44eb2a"

  strings:
    $s1 = "var OAt1 = new Array(\"\\x0a\",\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x44\",\"\\x49\",\"\\x6c\",\"\\x3d\",\"\\x22\",\"\\x6f" ascii

  condition:
    uint16(0) == 0x760a and
    all of them
}