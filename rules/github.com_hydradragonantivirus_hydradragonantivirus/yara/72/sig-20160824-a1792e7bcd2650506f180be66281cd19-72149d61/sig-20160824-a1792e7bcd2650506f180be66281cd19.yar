rule sig_20160824_a1792e7bcd2650506f180be66281cd19 {
  meta:
    description = "datamaliciousorder - file 20160824_a1792e7bcd2650506f180be66281cd19.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "80324e008b220fdbf66e285a5d8289b1c1ed397fcb125e4d504960e494d32af6"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}