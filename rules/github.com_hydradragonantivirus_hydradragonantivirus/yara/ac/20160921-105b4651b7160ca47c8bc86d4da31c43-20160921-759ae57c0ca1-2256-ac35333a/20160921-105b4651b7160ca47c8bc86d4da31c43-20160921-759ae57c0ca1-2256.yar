rule _20160921_105b4651b7160ca47c8bc86d4da31c43_20160921_759ae57c0ca1_2256 {
  meta:
    description = "datamaliciousorder - from files 20160921_105b4651b7160ca47c8bc86d4da31c43.js, 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_dc67677da64e0c03fb55538663264839.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e64d089e7076541ade19a5701fb8571545dde4a6c002b31df5fef02095005f7"
    hash2       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash3       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"

  strings:
    $s1 = "function fuck(){return \"Cd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){re" ascii
    $s2 = "urn \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"NKq\";})(),(f" ascii
    $s3 = ")(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DWe\";})(),(function fuck" ascii
    $s4 = "ck(){return \"Ik\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jh\";" ascii
    $s5 = "return \"DWe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s6 = "Cr\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"UOe\";})(),(function" ascii
    $s7 = "),(function fuck(){return \"DWe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(" ascii
    $s8 = "k(){return \"DWe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}