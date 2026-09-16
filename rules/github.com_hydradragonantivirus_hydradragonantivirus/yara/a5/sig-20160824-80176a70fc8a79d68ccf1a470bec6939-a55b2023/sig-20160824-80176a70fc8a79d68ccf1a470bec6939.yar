rule sig_20160824_80176a70fc8a79d68ccf1a470bec6939 {
  meta:
    description = "datamaliciousorder - file 20160824_80176a70fc8a79d68ccf1a470bec6939.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "38948cc6735a341441837a667f4c51a23aacd3e2da8893c8fba486bd514f26fe"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}