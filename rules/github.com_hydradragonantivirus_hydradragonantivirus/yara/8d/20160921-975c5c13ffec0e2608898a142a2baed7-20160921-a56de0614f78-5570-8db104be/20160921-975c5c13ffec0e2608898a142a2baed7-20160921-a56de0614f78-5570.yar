rule _20160921_975c5c13ffec0e2608898a142a2baed7_20160921_a56de0614f78_5570 {
  meta:
    description = "datamaliciousorder - from files 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_a56de0614f7815cff3fcb9f56233dbb4.js, 20160921_a65ac281dbfddbf6dbe63a0288de8c70.js, 20160921_d999dcba53f56b5a9c1abcc062fbeb80.js, 20160921_f1cc02f488792b7161849f8d15549315.js, 20160921_fa11dbc1cb358c8446ac1ba033c8a4c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash2       = "fa71b33b4ef1bf0fefff91c2876915e8ca80c82d473862703c383c6da0ad0186"
    hash3       = "5498e9d2bd6a9339a0b2314825151361bd8dd59a555d034973bbcac8e2cb195a"
    hash4       = "3bf893eeec71a95167368eb58abcbfe36362779b946b3e0d29c9032ec427ebd4"
    hash5       = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"
    hash6       = "27a60061641d8c44f2b882fcd06e72ca5721eaecb40ea10ad0b87c0c5f3c236f"

  strings:
    $s1 = "f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Qj" ascii
    $s2 = ")(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"DYs\";})(),(function f000" ascii
    $s3 = "f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"G" ascii
    $s4 = "urn \"Oe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s5 = "rn \"PTi\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}