rule _20160921_1bb9bdcf05b8f8acd28d5286e804d5cc_20160921_dbc1b5f3d038_1033 {
  meta:
    description = "datamaliciousorder - from files 20160921_1bb9bdcf05b8f8acd28d5286e804d5cc.js, 20160921_dbc1b5f3d0381a2cf3968267e55b6f78.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3937dec3a8d946e214facedccfe7f35e65dbd446a77d077a09996638d7524444"
    hash2       = "e37cb576da589586ca091f887f2d941f81f58c7a8c3974b4e11928357dfee825"

  strings:
    $s1  = "){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Py\";})" ascii
    $s2  = "(){return \"Py\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";" ascii
    $s3  = "eturn \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})()," ascii
    $s4  = "MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Cd\";})(),(functi" ascii
    $s5  = "(function fuck(){return \"CTm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Py\";})(),(function fuck(){re" ascii
    $s6  = "Ai\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(functio" ascii
    $s7  = "Go\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(functio" ascii
    $s8  = "\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xg\";})(),(function fu" ascii
    $s9  = "tion fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){retur" ascii
    $s10 = "uck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\"" ascii
    $s11 = "urn \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(" ascii
    $s12 = "n fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"I" ascii
    $s13 = "){return \"ZLd\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"MOj\";}" ascii
    $s14 = ")(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Py\";})(),(function fuck" ascii
    $s15 = "{return \"Cd\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s16 = "function fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){re" ascii
    $s17 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"" ascii
    $s18 = "n fuck(){return \"DWe\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}