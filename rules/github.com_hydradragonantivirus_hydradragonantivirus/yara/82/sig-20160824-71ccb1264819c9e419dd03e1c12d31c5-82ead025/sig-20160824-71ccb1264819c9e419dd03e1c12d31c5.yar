rule sig_20160824_71ccb1264819c9e419dd03e1c12d31c5 {
  meta:
    description = "datamaliciousorder - file 20160824_71ccb1264819c9e419dd03e1c12d31c5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bfeda4e322b130b7f82b0da41d4f0f139eccdc5c7ad36f3f2bba1a659bad91fb"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}