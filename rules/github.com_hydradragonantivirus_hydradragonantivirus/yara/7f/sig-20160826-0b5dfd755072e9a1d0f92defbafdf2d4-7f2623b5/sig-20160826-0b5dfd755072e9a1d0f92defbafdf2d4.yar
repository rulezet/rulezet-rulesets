rule sig_20160826_0b5dfd755072e9a1d0f92defbafdf2d4 {
  meta:
    description = "datamaliciousorder - file 20160826_0b5dfd755072e9a1d0f92defbafdf2d4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d06f7376955e2a7a1b40e053a910e1eff83435986ae5d8bd28b5841da2e94158"

  strings:
    $s1 = "var Ql = new Array(\"\\x66\"+\"\",\"\\x75\"+\"\",\"\\x6e\"+\"\",\"\\x63\"+\"\",\"\\x74\"+\"\",\"\\x69\"+\"\",\"\\x6f\"+\"\",\"" ascii

  condition:
    uint16(0) == 0x7566 and
    all of them
}