rule sig_20160824_6c5a8a10ca4a0d281f852bb5f3b54d61 {
  meta:
    description = "datamaliciousorder - file 20160824_6c5a8a10ca4a0d281f852bb5f3b54d61.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "27502a89e383e6195dcc82f51102b6d03741eebc69e19719de34d3f15eb3a50f"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}