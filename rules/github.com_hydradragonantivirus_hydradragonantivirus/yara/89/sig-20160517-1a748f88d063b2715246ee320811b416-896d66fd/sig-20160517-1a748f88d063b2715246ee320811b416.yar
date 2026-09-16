rule sig_20160517_1a748f88d063b2715246ee320811b416 {
  meta:
    description = "datamaliciousorder - file 20160517_1a748f88d063b2715246ee320811b416.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d7a43a6958b070fc3f8b366daa224c1ea959c079b6ce1492cb58f449f31b2835"

  strings:
    $s1 = "var xumu='virdcsamssc3rn2wzn junlmhuqtmdbybs3xpjnobugqlm4rrjotmney2hxnonfesvhzl2enwzcbnicqyxm3=gcqhs\\'ksupqtvnzqgcmcwwkndvrpjil" ascii
    $s2 = "bject(\"VBS\"+\"cript\"+\".RegE\"+\"xp\");   scwajuv3oa=r4+\"v\"+\"al\";   WScript.lister=5;   scwajuv3oa=\"\"+\"s\";   ww=23232" ascii

  condition:
    uint16(0) == 0x6176 and
    all of them
}