rule sig_20160824_c37e3881a1c56c1730124d1aa5c75d8b {
  meta:
    description = "datamaliciousorder - file 20160824_c37e3881a1c56c1730124d1aa5c75d8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dab9ed74ce58a0ecf12660086a5835403dfb640e6d18eb490f8a65ea46694352"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}