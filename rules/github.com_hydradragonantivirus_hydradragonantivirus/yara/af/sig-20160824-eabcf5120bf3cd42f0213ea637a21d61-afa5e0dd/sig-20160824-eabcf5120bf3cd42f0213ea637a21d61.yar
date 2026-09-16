rule sig_20160824_eabcf5120bf3cd42f0213ea637a21d61 {
  meta:
    description = "datamaliciousorder - file 20160824_eabcf5120bf3cd42f0213ea637a21d61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3b27b32491f552c1e2e92da568fd895c745a9e66cb939cd64c7965b88544b8e6"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}