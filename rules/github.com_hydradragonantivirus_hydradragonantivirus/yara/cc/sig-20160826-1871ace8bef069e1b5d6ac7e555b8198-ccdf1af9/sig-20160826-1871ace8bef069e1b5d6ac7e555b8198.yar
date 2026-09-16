rule sig_20160826_1871ace8bef069e1b5d6ac7e555b8198 {
  meta:
    description = "datamaliciousorder - file 20160826_1871ace8bef069e1b5d6ac7e555b8198.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a378f62c242303c3dcfac044335bd203aac847080f66f56cbadfe2cd296b72e0"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}