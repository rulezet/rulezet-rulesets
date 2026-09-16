rule sig_20160824_0fe40d96c271dcb3ab436a21a333691c {
  meta:
    description = "datamaliciousorder - file 20160824_0fe40d96c271dcb3ab436a21a333691c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3345c728f92339ff5955f1e58e62fda8108849c1a11498b810d56c9a20412e0c"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}