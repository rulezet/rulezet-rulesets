rule sig_20160826_494ce95fdcacaf30c14e3e454b5a78ac {
  meta:
    description = "datamaliciousorder - file 20160826_494ce95fdcacaf30c14e3e454b5a78ac.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6f1cfd7203efbe93f5801e5fdf87b46a693585e1f85a14dff773342ddae8f466"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}