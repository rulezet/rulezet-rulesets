rule _20160921_a8b3df7e98e8a886568b517b6d357d72_20160921_ac32e5db1761_1516 {
  meta:
    description = "datamaliciousorder - from files 20160921_a8b3df7e98e8a886568b517b6d357d72.js, 20160921_ac32e5db1761db7bcee12f6443e4be71.js, 20160921_b9eadd20f28216849138290cb6dac4de.js, 20160921_dd3003e8f16270410cd847da3878f1fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0652be8fe8ee502a5c45d7c0d1b7f5ea93bd8633350801afbb4709b88afc93e2"
    hash2       = "c720e572402df240156cf5af93a10b135edc995ca3aaedbfe6a9673216f7c930"
    hash3       = "4859166acfe74b9a623acc55b045aff7a4c46e4f5c457bb304c5169c6e7fb4a9"
    hash4       = "484cc3f4c9cc3a29ae3ad53bb6d47be99d119531836a636c664a77fc891b38fc"

  strings:
    $s1  = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"" ascii
    $s2  = "on fuck(){return \"DHd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return " ascii
    $s3  = "return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s4  = "(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){r" ascii
    $s5  = "){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";}" ascii
    $s6  = "rn \"GJx\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s7  = "})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuc" ascii
    $s8  = "ction fuck(){return \"RAi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return" ascii
    $s9  = "n fuck(){return \"Pc\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"G" ascii
    $s10 = "})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fu" ascii
    $s11 = "g\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function " ascii
    $s12 = "{return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ik\";})(" ascii
    $s13 = "uck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}