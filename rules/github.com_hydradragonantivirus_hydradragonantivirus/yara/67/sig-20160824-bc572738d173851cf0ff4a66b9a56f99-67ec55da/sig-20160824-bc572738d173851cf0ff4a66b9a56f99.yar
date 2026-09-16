rule sig_20160824_bc572738d173851cf0ff4a66b9a56f99 {
  meta:
    description = "datamaliciousorder - file 20160824_bc572738d173851cf0ff4a66b9a56f99.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6db1ae3ce3d8c43501e5f13ebd4c1caaa42998f611896b88a57441cd20c3576d"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}