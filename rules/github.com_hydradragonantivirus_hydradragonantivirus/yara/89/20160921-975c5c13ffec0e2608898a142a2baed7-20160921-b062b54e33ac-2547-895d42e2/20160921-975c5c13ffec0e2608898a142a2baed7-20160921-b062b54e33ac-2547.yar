rule _20160921_975c5c13ffec0e2608898a142a2baed7_20160921_b062b54e33ac_2547 {
  meta:
    description = "datamaliciousorder - from files 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_b062b54e33ac394b0c1a389b161f5cb6.js, 20160921_f1cc02f488792b7161849f8d15549315.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash2       = "5d0516ba7ba35ed307fd316146755f07fe542904a37fc2e0bb6a28a59cb06139"
    hash3       = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"

  strings:
    $s1 = "on f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s2 = ",(function f000(){return \"Vj\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"MDb\";})(),(function f000(){r" ascii
    $s3 = ")(),(function f000(){return \"MDb\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Km\";})(),(function f000" ascii
    $s4 = "0(){return \"Vj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"MDb\";}" ascii
    $s5 = "urn \"MDb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s6 = "\";})(),(function f000(){return \"MDb\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"ZIi\";})(),(function " ascii
    $s7 = " f000(){return \"HJm\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MD" ascii
    $s8 = "tion f000(){return \"HJm\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}