rule sig_20160824_11744d6f570f9997ce9fc80ffef429a3 {
  meta:
    description = "datamaliciousorder - file 20160824_11744d6f570f9997ce9fc80ffef429a3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a4d18e3c44908746c716bfed4f2ee1c9f6fd27f3ee1f1a01d908d323d44de33a"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}