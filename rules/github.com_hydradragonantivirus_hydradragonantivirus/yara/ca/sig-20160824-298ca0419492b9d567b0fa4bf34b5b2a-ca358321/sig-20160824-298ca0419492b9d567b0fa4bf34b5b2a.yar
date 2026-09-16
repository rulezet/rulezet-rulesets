rule sig_20160824_298ca0419492b9d567b0fa4bf34b5b2a {
  meta:
    description = "datamaliciousorder - file 20160824_298ca0419492b9d567b0fa4bf34b5b2a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ffb2ebe9bc54b1dc8fe9a92e74f393909c84f613781746e2d9a7b3793a395257"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}