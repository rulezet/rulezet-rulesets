rule _20160921_5e30fe0c691277f3c6d0814d796ba918_20160921_f5230fc58405_578 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e30fe0c691277f3c6d0814d796ba918.js, 20160921_f5230fc58405f25233bda6815654bd6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cac2594d8c0286d3110fd3705816d41052df49790da39881cedd79b8cb5c6ed"
    hash2       = "1a813dda7d0088c45bb00563ea79982995ec1337c805380117fe705f80c51c64"

  strings:
    $s1  = "rn \"OQr\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Av\";})(),(fu" ascii
    $s2  = "){return \"Py\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})" ascii
    $s3  = "urn \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"YAv\";})(),(f" ascii
    $s4  = "ction fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s5  = "\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function f" ascii
    $s6  = "tion fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return " ascii
    $s7  = "uck(){return \"IKv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py" ascii
    $s8  = "return \"XCr\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii
    $s9  = "turn \"ADy\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s10 = "n fuck(){return \"Py\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"G" ascii
    $s11 = "ion fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return " ascii
    $s12 = "),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck()" ascii
    $s13 = "(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"NKq\";})(),(function fuck()" ascii
    $s14 = "unction fuck(){return \"ADy\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){ret" ascii
    $s15 = "){return \"LGo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})" ascii
    $s16 = "uck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn" ascii
    $s17 = "){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Py\";})(" ascii
    $s18 = "turn \"MBg\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"YAv\";})(),(" ascii
    $s19 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return" ascii
    $s20 = " \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Za\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}