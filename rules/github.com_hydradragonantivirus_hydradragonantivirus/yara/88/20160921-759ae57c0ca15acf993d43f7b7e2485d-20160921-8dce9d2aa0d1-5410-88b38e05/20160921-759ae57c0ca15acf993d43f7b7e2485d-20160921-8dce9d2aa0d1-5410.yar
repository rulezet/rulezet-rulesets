rule _20160921_759ae57c0ca15acf993d43f7b7e2485d_20160921_8dce9d2aa0d1_5410 {
  meta:
    description = "datamaliciousorder - from files 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_8dce9d2aa0d1e296bbcc31a437e35a45.js, 20160921_c07f026b9458324f489ec08b7859e758.js, 20160921_dc67677da64e0c03fb55538663264839.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash2       = "26c784fc7a8e4ee1608e66a82f1ba134972418c5968433b39f54392e7f3de0f2"
    hash3       = "ea2be3685bc68d327f9689a9fc4de597314db751f1eacc3ff5fbee0dd0397db0"
    hash4       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"

  strings:
    $s1 = "ion fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s2 = "\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function f" ascii
    $s3 = "(){return \"IKv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";}" ascii
    $s4 = "fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NK" ascii
    $s5 = "uck(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}