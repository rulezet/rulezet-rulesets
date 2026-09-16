rule sig_20160824_9b04558eba93abe9336a72dffda43242 {
  meta:
    description = "datamaliciousorder - file 20160824_9b04558eba93abe9336a72dffda43242.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d39f69b8efa90b8ddce181733d27398c9d42f8c0abffd47ebefdc711878a8325"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}