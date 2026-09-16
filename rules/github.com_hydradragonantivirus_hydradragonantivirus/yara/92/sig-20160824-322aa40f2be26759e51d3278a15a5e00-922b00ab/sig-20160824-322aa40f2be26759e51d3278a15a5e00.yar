rule sig_20160824_322aa40f2be26759e51d3278a15a5e00 {
  meta:
    description = "datamaliciousorder - file 20160824_322aa40f2be26759e51d3278a15a5e00.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "357aec6277e9b611ba507e3e0d2ee92c4138390c46984dcce5ff66704da9a29b"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}