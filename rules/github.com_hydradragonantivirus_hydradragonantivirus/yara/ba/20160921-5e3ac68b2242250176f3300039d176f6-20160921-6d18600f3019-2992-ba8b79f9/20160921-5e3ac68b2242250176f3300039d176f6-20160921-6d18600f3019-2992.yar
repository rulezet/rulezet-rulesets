rule _20160921_5e3ac68b2242250176f3300039d176f6_20160921_6d18600f3019_2992 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e3ac68b2242250176f3300039d176f6.js, 20160921_6d18600f3019656b0ab414a3d1a69ddb.js, 20160921_b062b54e33ac394b0c1a389b161f5cb6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "89b3eb7dc82702c0fd809112cd45d647e28906b665dcfd9718254fadc25580e9"
    hash2       = "fb0471dc4828588d37d01ddaa7b9454e82acacc4dfdd9f0998b461661e3810db"
    hash3       = "5d0516ba7ba35ed307fd316146755f07fe542904a37fc2e0bb6a28a59cb06139"

  strings:
    $s1 = "rn \"HJm\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(f" ascii
    $s2 = "z\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s3 = "ion f000(){return \"Km\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return " ascii
    $s4 = "ion f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"MBb\";})(),(function f000(){return " ascii
    $s5 = "function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){ret" ascii
    $s6 = "(),(function f000(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Go\";})(),(function f000(" ascii
    $s7 = "f000(){return \"Tn\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}