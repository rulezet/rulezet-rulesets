rule sig_20160824_da41416e11509bd5e7cda2d4a2b149ab {
  meta:
    description = "datamaliciousorder - file 20160824_da41416e11509bd5e7cda2d4a2b149ab.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bc301067a4ab194b5cf1873bf85b405dd87083f3c5c09b83d3c6f6f333465b41"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}