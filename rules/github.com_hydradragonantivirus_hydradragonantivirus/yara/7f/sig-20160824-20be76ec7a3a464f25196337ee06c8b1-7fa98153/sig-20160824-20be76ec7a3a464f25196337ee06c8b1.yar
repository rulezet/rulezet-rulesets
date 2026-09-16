rule sig_20160824_20be76ec7a3a464f25196337ee06c8b1 {
  meta:
    description = "datamaliciousorder - file 20160824_20be76ec7a3a464f25196337ee06c8b1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ed881c7e793fa15f6d5083dcfb97133a7e79c93fef3b40efd4a166c5d1503039"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}