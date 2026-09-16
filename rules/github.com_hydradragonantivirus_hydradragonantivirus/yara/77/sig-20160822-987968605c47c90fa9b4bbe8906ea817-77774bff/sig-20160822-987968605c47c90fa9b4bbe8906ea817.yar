rule sig_20160822_987968605c47c90fa9b4bbe8906ea817 {
  meta:
    description = "datamaliciousorder - file 20160822_987968605c47c90fa9b4bbe8906ea817.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b4d3303c7dff7b8f7f26ecdb3f0e57c9c0e8feec88d02f6e60f48a3ce8a79e19"

  strings:
    $s1 = "var Cp = new Array(\"\\x76\",\"\\x61\",\"\\x72\",\"\\x20\",\"\\x5f\",\"\\x77\",\"\\x73\",\"\\x63\",\"\\x69\",\"\\x70\",\"\\x74\"" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}