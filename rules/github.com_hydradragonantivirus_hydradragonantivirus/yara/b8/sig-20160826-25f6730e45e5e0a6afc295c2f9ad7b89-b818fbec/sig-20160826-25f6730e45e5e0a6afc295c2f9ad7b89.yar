rule sig_20160826_25f6730e45e5e0a6afc295c2f9ad7b89 {
  meta:
    description = "datamaliciousorder - file 20160826_25f6730e45e5e0a6afc295c2f9ad7b89.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fc3ad7be9eb61f30309c9788bb4f56ae2f0c84c2619334f860b4c40cacb98d13"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}