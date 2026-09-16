rule sig_20160824_c4305d903f8305b7b09e27ea238fb3f0 {
  meta:
    description = "datamaliciousorder - file 20160824_c4305d903f8305b7b09e27ea238fb3f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "76a993942eccd018e0ca37a391918b962d4aad71304e21eae08b13d4776b0532"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}