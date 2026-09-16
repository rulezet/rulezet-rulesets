rule sig_20160826_07a37bd8e880a7d5a2bc1f4f36127aaa {
  meta:
    description = "datamaliciousorder - file 20160826_07a37bd8e880a7d5a2bc1f4f36127aaa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "dcc963cafbb0784367c31e634ee2676e600ae4b09d00c6a7dc7941ae8279430f"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}