rule _20160921_4d30edc3a4e3226feee5b6289df9e399_20160921_759ae57c0ca1_5138 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d30edc3a4e3226feee5b6289df9e399.js, 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_dc67677da64e0c03fb55538663264839.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"
    hash2       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash3       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"

  strings:
    $s1 = ")(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Nm\";})(),(function fuck()" ascii
    $s2 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(function fuck" ascii
    $s3 = "ck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Jo" ascii
    $s4 = "nction fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retu" ascii
    $s5 = "fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}