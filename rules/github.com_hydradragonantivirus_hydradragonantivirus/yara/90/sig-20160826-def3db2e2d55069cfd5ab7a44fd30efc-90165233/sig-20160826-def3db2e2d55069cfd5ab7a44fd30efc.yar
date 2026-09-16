rule sig_20160826_def3db2e2d55069cfd5ab7a44fd30efc {
  meta:
    description = "datamaliciousorder - file 20160826_def3db2e2d55069cfd5ab7a44fd30efc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ac210d92dc378180ed824b836a23a6d6a2957fd5b2d10dc65a4048620d387af"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}