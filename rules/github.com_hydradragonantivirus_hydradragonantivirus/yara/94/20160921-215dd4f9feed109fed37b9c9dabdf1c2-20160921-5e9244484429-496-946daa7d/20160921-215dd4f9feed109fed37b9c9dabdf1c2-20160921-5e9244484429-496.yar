rule _20160921_215dd4f9feed109fed37b9c9dabdf1c2_20160921_5e9244484429_496 {
  meta:
    description = "datamaliciousorder - from files 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js, 20160921_5e9244484429cd897ec88fe97140c29c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"
    hash2       = "002e6ee9d0d9e7f54ead7f8981f20be210819f7a75c52e3d1e91de2fd03ada17"

  strings:
    $s1  = " \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"We\";})(),(func" ascii
    $s2  = "nction fuck(){return \"Jo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retu" ascii
    $s3  = "uck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"PDf" ascii
    $s4  = "\"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Xg\";})(),(functi" ascii
    $s5  = "rn \"YAv\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"GNm\";})(),(fu" ascii
    $s6  = "n \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(fu" ascii
    $s7  = "u\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Jh\";})(),(function f" ascii
    $s8  = "n \"LGo\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MIl\";})(),(fu" ascii
    $s9  = ";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Jo\";})(),(function fu" ascii
    $s10 = "return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"PDf\";})(" ascii
    $s11 = "ion fuck(){return \"LGo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s12 = "\"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"ADy\";})(),(fun" ascii
    $s13 = " \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s14 = "eturn \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(" ascii
    $s15 = "turn \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(" ascii
    $s16 = "})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fu" ascii
    $s17 = "){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";}" ascii
    $s18 = "fuck(){return \"Jo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IR" ascii
    $s19 = "LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s20 = "ck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}