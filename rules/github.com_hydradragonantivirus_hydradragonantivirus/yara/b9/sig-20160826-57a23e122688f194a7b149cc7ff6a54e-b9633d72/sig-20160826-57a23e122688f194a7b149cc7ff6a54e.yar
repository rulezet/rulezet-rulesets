rule sig_20160826_57a23e122688f194a7b149cc7ff6a54e {
  meta:
    description = "datamaliciousorder - file 20160826_57a23e122688f194a7b149cc7ff6a54e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3bec793a4a5ae889de91ff267de8f930173c371222395684d3f106a6efb90e0e"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}