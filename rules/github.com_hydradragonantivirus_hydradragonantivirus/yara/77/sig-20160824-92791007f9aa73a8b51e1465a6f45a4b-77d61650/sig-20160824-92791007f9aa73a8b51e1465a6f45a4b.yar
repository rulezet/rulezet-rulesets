rule sig_20160824_92791007f9aa73a8b51e1465a6f45a4b {
  meta:
    description = "datamaliciousorder - file 20160824_92791007f9aa73a8b51e1465a6f45a4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "19e570347759f00ed2065db64454271923d3adeccea300278544b1f27f350415"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}