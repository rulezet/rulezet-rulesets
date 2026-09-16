rule sig_20160826_dee35ff7850dc0f9b368b628554b29d4 {
  meta:
    description = "datamaliciousorder - file 20160826_dee35ff7850dc0f9b368b628554b29d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7ef506bccce301b0dddb9d30e522414c53478eaf64b93034cc9b0019e3521bc8"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}