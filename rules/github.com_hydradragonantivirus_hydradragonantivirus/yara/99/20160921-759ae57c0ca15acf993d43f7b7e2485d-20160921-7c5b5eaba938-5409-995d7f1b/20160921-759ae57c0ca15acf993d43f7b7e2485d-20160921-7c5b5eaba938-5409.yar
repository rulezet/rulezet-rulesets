rule _20160921_759ae57c0ca15acf993d43f7b7e2485d_20160921_7c5b5eaba938_5409 {
  meta:
    description = "datamaliciousorder - from files 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_7c5b5eaba938fa91eb6a9414212e13f9.js, 20160921_dc67677da64e0c03fb55538663264839.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash2       = "9b25331c24a00cfccf7bf1604f7df1d245543734bf5553f0a7c3c911bb74cbb8"
    hash3       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"

  strings:
    $s1 = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){" ascii
    $s2 = " fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn" ascii
    $s3 = "Pu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Hs\";})(),(function" ascii
    $s4 = "turn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"SUi\";})()," ascii
    $s5 = "on fuck(){return \"YQt\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}