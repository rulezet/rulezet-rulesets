rule sig_20160826_95a791b734007000e298a34b72e9ee6b {
  meta:
    description = "datamaliciousorder - file 20160826_95a791b734007000e298a34b72e9ee6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a21bec312fcd94648482c236d4cc986124f5ed8e1c13f98bd0c93a099da4c12e"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}