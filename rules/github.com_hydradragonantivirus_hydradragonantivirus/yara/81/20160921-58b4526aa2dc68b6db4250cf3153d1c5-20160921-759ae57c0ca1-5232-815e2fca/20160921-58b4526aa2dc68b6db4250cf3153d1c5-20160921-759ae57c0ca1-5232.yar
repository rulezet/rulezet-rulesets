rule _20160921_58b4526aa2dc68b6db4250cf3153d1c5_20160921_759ae57c0ca1_5232 {
  meta:
    description = "datamaliciousorder - from files 20160921_58b4526aa2dc68b6db4250cf3153d1c5.js, 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js, 20160921_dc67677da64e0c03fb55538663264839.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8879fc10234de7d36f536a9cdb49bc5cf37dfb897d610b0eeba644033852dd92"
    hash2       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash3       = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"
    hash4       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"

  strings:
    $s1 = "k(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd" ascii
    $s2 = "rn \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s3 = "urn \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(f" ascii
    $s4 = " fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np" ascii
    $s5 = " \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}