rule sig_20160824_675f8d0994de63f19834b2fab238d84d {
  meta:
    description = "datamaliciousorder - file 20160824_675f8d0994de63f19834b2fab238d84d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "060bf82962d22bbe9e66ee41ee6bb4da1d8a01151d3ac4272522d516b76a4c9a"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}