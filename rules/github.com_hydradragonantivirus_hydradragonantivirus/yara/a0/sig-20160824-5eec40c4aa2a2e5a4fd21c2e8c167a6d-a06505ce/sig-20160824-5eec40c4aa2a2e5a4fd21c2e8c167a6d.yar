rule sig_20160824_5eec40c4aa2a2e5a4fd21c2e8c167a6d {
  meta:
    description = "datamaliciousorder - file 20160824_5eec40c4aa2a2e5a4fd21c2e8c167a6d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "93af8813adf5d01e067bc5e18ba7be9109dded3dfa0c509bfc125ac900b051e9"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}