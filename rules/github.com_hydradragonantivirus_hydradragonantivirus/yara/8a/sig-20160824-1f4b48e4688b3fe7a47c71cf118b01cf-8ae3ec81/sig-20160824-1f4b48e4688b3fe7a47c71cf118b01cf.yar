rule sig_20160824_1f4b48e4688b3fe7a47c71cf118b01cf {
  meta:
    description = "datamaliciousorder - file 20160824_1f4b48e4688b3fe7a47c71cf118b01cf.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2f6a77506df6b610f185af081e7e89bf0acfcf6cb2e2308cad93bd930ca3e09"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}