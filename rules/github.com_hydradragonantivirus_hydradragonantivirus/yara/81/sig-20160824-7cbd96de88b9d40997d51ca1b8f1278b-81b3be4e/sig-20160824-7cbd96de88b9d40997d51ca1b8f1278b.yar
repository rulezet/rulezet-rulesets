rule sig_20160824_7cbd96de88b9d40997d51ca1b8f1278b {
  meta:
    description = "datamaliciousorder - file 20160824_7cbd96de88b9d40997d51ca1b8f1278b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3cfaf8cac912a43ade0e8c988e8876dac8df5be2a3bc4cc433dec26a3a40edfd"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}