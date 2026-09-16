rule _20160921_37aa38f76e02afb64903280105ce4597_20160921_b8c98d7e4e5c_4913 {
  meta:
    description = "datamaliciousorder - from files 20160921_37aa38f76e02afb64903280105ce4597.js, 20160921_b8c98d7e4e5c69c2f4fa4fec37a59dfb.js, 20160921_fe8abdad2bc00d1378e2964402e33217.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "768a32c669c193375bb8e7adb97cdbb697cd6f4f09fb5dc67bb63e62b7de29cf"
    hash2       = "f1ea05bc317ec861954db64b30bd293d8ee2f663106d48389d91cfb77247fb1e"
    hash3       = "39d0496129988da40dbbddcff6610a39be1f05ddd7f48a13058b749810c8400d"

  strings:
    $s1 = "n f000(){return \"QDg\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s2 = "eturn \"DYs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Oe\";})()," ascii
    $s3 = "urn \"Yz\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"TKl\";})(),(" ascii
    $s4 = "\"MKa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"UEg\";})(),(func" ascii
    $s5 = "0(){return \"Oe\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"BIj\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}