rule sig_20160824_6c4400857f7d69ce9201f32c148958b7 {
  meta:
    description = "datamaliciousorder - file 20160824_6c4400857f7d69ce9201f32c148958b7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6a246aaa5d1156cffd4b5d9dc588120073e062ca1bb5d968283ae17ed976d942"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}