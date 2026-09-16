rule sig_20160824_93febfff9f9771fedbf044f864d3a070 {
  meta:
    description = "datamaliciousorder - file 20160824_93febfff9f9771fedbf044f864d3a070.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "10e0a259317e52d033050a210673420ce0b4010731f1b1f82c391b5e24356a45"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}