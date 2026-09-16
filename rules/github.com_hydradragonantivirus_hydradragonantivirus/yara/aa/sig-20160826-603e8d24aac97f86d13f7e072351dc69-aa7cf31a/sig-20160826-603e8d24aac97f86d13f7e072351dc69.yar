rule sig_20160826_603e8d24aac97f86d13f7e072351dc69 {
  meta:
    description = "datamaliciousorder - file 20160826_603e8d24aac97f86d13f7e072351dc69.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "75ecf0c76971aaaccf094f341c5dfb5d2f6927a8d036c179115ad8e20f9fbf48"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}