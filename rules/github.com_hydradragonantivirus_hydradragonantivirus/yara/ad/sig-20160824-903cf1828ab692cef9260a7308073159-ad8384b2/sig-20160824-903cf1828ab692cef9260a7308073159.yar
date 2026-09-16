rule sig_20160824_903cf1828ab692cef9260a7308073159 {
  meta:
    description = "datamaliciousorder - file 20160824_903cf1828ab692cef9260a7308073159.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "faad42fa1ed0b728702f438ea8dd13ad76c2816a3ba7b49e8954a6f339f23edc"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}