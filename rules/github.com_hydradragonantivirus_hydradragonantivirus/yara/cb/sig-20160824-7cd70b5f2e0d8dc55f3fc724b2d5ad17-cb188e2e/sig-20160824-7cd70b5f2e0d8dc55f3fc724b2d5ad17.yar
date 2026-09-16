rule sig_20160824_7cd70b5f2e0d8dc55f3fc724b2d5ad17 {
  meta:
    description = "datamaliciousorder - file 20160824_7cd70b5f2e0d8dc55f3fc724b2d5ad17.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3773a6b2dab3477e68bf3e0ebd6b681b9347a1263066881a5cb1d9198474e84f"

  strings:
    $s1 = "var Li4 = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}