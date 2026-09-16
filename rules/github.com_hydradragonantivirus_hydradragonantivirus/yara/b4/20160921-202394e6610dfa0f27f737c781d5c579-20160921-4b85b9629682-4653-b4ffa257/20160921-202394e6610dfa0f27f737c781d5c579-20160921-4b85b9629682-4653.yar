rule _20160921_202394e6610dfa0f27f737c781d5c579_20160921_4b85b9629682_4653 {
  meta:
    description = "datamaliciousorder - from files 20160921_202394e6610dfa0f27f737c781d5c579.js, 20160921_4b85b9629682d9cbd379b3404bd09eb1.js, 20160921_8471da3d602dedb9a4749d6e2c757b47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d10df61dcb3a781b5266597c0f1a9d52066cebbebf5196ad93fd81855575ed11"
    hash2       = "43de7c579d15cb70a31da759a94145ff9a831b9bf0e5ff93ae38b5064231b62f"
    hash3       = "98a5a561c128a716a07f6503ae8144cb9404c06eb1a2796af84924653c81967c"

  strings:
    $s1 = "n\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"XTn\";})(),(function" ascii
    $s2 = "nction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Um\";})(),(function f000(){retu" ascii
    $s3 = "h\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s4 = "tion f000(){return \"DAp\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return" ascii
    $s5 = "0(){return \"IAa\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}