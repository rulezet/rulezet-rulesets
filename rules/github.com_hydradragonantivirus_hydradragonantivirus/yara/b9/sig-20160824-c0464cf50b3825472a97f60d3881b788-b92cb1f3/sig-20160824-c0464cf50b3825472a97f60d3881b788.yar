rule sig_20160824_c0464cf50b3825472a97f60d3881b788 {
  meta:
    description = "datamaliciousorder - file 20160824_c0464cf50b3825472a97f60d3881b788.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7db19efde563115d611cc4621e7996ca99ffdfa931a06f8d3d14b9390c7ca271"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}