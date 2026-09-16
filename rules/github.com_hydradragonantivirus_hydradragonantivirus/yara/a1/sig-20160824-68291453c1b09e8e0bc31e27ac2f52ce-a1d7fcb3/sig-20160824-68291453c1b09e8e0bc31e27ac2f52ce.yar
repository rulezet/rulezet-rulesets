rule sig_20160824_68291453c1b09e8e0bc31e27ac2f52ce {
  meta:
    description = "datamaliciousorder - file 20160824_68291453c1b09e8e0bc31e27ac2f52ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "deacfd557cf7ea9fadf60d7ee6b9a6316626fb33bb4c53a448be850f95afe26a"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}