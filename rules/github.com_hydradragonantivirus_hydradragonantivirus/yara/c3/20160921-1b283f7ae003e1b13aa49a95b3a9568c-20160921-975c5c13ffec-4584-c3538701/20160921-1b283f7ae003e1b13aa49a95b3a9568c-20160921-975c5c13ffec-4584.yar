rule _20160921_1b283f7ae003e1b13aa49a95b3a9568c_20160921_975c5c13ffec_4584 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b283f7ae003e1b13aa49a95b3a9568c.js, 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_f1cc02f488792b7161849f8d15549315.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a9b43cd6462f0f7b7e48c84642e70cda1bfb372344d51b33be67bcc3e2e2a374"
    hash2       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash3       = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"

  strings:
    $s1 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){retur" ascii
    $s2 = "00(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZIi\"" ascii
    $s3 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"RLk\";})(),(function f00" ascii
    $s4 = "ction f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Km\";})(),(function f000(){retur" ascii
    $s5 = "urn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"NYh\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}