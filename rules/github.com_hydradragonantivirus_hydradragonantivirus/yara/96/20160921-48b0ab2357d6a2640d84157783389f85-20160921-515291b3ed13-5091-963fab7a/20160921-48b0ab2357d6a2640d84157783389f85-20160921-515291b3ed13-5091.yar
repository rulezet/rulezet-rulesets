rule _20160921_48b0ab2357d6a2640d84157783389f85_20160921_515291b3ed13_5091 {
  meta:
    description = "datamaliciousorder - from files 20160921_48b0ab2357d6a2640d84157783389f85.js, 20160921_515291b3ed13de9fe2933a326bc71920.js, 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_87ced6523e47b3b752b2353107bc989a.js, 20160921_945a46518061bd8e157aed251e0ffa9e.js, 20160921_dc67677da64e0c03fb55538663264839.js, 20160921_f5230fc58405f25233bda6815654bd6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fee375f08ae5432a47f4a4a8fefed2cbbb6e1484d8914742942e60f703c8f7f0"
    hash2       = "6deef7cfd2f4743f897d0043907a6481545f6a96b01c76c7d81d02348a2a17e0"
    hash3       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash4       = "46c521beb23d37cfa4d60cfcab38c941734971fe3102123b7e4c2813544d39b6"
    hash5       = "cc3d236edb3b45a767b438fa21243a07176d6f5def724e03e45aca76b3127054"
    hash6       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"
    hash7       = "1a813dda7d0088c45bb00563ea79982995ec1337c805380117fe705f80c51c64"

  strings:
    $s1 = "return \"MBg\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(" ascii
    $s2 = "ion fuck(){return \"Ik\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return " ascii
    $s3 = ")(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(" ascii
    $s4 = "turn \"Pc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Yk\";})(),(fu" ascii
    $s5 = "nction fuck(){return \"GJx\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}