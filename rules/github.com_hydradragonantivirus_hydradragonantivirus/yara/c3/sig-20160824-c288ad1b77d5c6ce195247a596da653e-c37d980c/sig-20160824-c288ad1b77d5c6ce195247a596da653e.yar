rule sig_20160824_c288ad1b77d5c6ce195247a596da653e {
  meta:
    description = "datamaliciousorder - file 20160824_c288ad1b77d5c6ce195247a596da653e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c041d6395a400d1801798cad388f92ea30148d66dd86b47bfaa5d031f8d382d"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}