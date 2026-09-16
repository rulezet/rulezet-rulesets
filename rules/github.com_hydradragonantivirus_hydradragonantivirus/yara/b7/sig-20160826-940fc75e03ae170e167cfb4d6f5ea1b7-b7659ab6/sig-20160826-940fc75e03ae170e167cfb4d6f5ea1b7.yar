rule sig_20160826_940fc75e03ae170e167cfb4d6f5ea1b7 {
  meta:
    description = "datamaliciousorder - file 20160826_940fc75e03ae170e167cfb4d6f5ea1b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "55a8e7f02b0f9cf93f259716e42fd65fbc0667cc3ab3d63725e8a4f3bc5acb5c"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}