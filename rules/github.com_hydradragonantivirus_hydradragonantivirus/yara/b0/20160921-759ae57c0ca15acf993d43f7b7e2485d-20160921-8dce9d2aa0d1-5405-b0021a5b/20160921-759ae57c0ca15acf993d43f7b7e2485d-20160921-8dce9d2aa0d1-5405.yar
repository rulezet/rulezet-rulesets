rule _20160921_759ae57c0ca15acf993d43f7b7e2485d_20160921_8dce9d2aa0d1_5405 {
  meta:
    description = "datamaliciousorder - from files 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_8dce9d2aa0d1e296bbcc31a437e35a45.js, 20160921_abc9044816c2455dc24ac338746b6bd5.js, 20160921_dc67677da64e0c03fb55538663264839.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash2       = "26c784fc7a8e4ee1608e66a82f1ba134972418c5968433b39f54392e7f3de0f2"
    hash3       = "2bb53920235afb1c2d16f013bc118d1df64065eefc10c1b2b9e7a4b133850850"
    hash4       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"

  strings:
    $s1 = "{return \"IKv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})" ascii
    $s2 = "n \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(f" ascii
    $s3 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"" ascii
    $s4 = "n \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})(),(fu" ascii
    $s5 = "fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LG" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}