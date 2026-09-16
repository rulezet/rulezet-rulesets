rule sig_20160826_9bb711c22938fb4ae33b943142609a27 {
  meta:
    description = "datamaliciousorder - file 20160826_9bb711c22938fb4ae33b943142609a27.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "227f2941c76d756b79d4d59b66bc82f8140af8b305bab9fd92e5d87e3ba86c26"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}