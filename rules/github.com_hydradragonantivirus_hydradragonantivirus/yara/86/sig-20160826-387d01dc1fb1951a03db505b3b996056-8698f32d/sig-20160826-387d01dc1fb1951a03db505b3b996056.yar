rule sig_20160826_387d01dc1fb1951a03db505b3b996056 {
  meta:
    description = "datamaliciousorder - file 20160826_387d01dc1fb1951a03db505b3b996056.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f1594f672cd1dd39e5071deec79a77711839fe4867219922a45bad1c6f090005"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}