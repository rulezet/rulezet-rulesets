rule sig_20160824_991fab23186795d8256c18813fd5a159 {
  meta:
    description = "datamaliciousorder - file 20160824_991fab23186795d8256c18813fd5a159.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "641cc5a9882de7e81355be45cb4a8cf91c944e2f85b463bab7c3ef50733a320b"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}