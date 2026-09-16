rule sig_20160826_9d18b9a7d19adec81c6fcd5dd42ad4cc {
  meta:
    description = "datamaliciousorder - file 20160826_9d18b9a7d19adec81c6fcd5dd42ad4cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c3cd8cb80e8d55a3c197be7cb951dee53e0b31bd65666146736d42130ab684b9"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}