rule _20160921_1bb9bdcf05b8f8acd28d5286e804d5cc_20160921_378cbd2e2764_1454 {
  meta:
    description = "datamaliciousorder - from files 20160921_1bb9bdcf05b8f8acd28d5286e804d5cc.js, 20160921_378cbd2e27643682973c633e59454f9f.js, 20160921_9b80c329004df146d978cb7b31b22c05.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3937dec3a8d946e214facedccfe7f35e65dbd446a77d077a09996638d7524444"
    hash2       = "8ce016002e44e1fbf4624122138e5a8b0261aff6487c52da0d644398da46a896"
    hash3       = "d0ec644cd7307cbd280d369539e9834d3ad2ba0909b631b5a3640f8f6a1105d1"

  strings:
    $s1  = " fuck(){return \"GWo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"" ascii
    $s2  = "(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XCr\"" ascii
    $s3  = ";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"IOs\";})(),(function fu" ascii
    $s4  = "on fuck(){return \"GWo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s5  = "k(){return \"Jh\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";" ascii
    $s6  = "n fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s7  = "{return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GJx\";})" ascii
    $s8  = "(function fuck(){return \"Qh\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s9  = ")(),(function fuck(){return \"Av\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\";})(),(function fuck(" ascii
    $s10 = "urn \"TTs\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Dc\";})(),(fu" ascii
    $s11 = "DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"DAa\";})(),(functi" ascii
    $s12 = "Py\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii
    $s13 = " \"Tv\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"IPu\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}