rule sig_20160824_74d9856a5e8c17cd7c7af5145e898913 {
  meta:
    description = "datamaliciousorder - file 20160824_74d9856a5e8c17cd7c7af5145e898913.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9f912d7c48c9eb8b55934e801e7928e60f1960696620db720038746554a46a30"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}