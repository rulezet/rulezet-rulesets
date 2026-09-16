rule sig_20160824_8c7c58e28b599fb9b0fbc44f086cacf4 {
  meta:
    description = "datamaliciousorder - file 20160824_8c7c58e28b599fb9b0fbc44f086cacf4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "07130dd409a3d7752c2870956a5aa04cd8aaa646a8e26092929fd391f85733da"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}