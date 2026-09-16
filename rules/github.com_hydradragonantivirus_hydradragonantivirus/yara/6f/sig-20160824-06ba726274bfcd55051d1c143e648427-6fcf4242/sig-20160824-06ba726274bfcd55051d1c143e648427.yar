rule sig_20160824_06ba726274bfcd55051d1c143e648427 {
  meta:
    description = "datamaliciousorder - file 20160824_06ba726274bfcd55051d1c143e648427.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bee12027e52193e185b8c1ad2040c4d709140a636ba3726bfef05df9f2f2a41a"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}