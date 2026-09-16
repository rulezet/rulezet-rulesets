rule sig_20160824_ea9651448773217ec31385964c22aa65 {
  meta:
    description = "datamaliciousorder - file 20160824_ea9651448773217ec31385964c22aa65.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e881fd2a16a3e42ac23612b802089441dcf256663ecdf24163fe53aed6da913d"

  strings:
    $s1 = "var DOh = new Array(\"\\x66\",\"\\x75\",\"\\x6e\",\"\\x63\",\"\\x74\",\"\\x69\",\"\\x6f\",\"\\x20\",\"\\x6b\",\"\\x28\",\"\\x29" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}