rule _20160921_41f7b3abc606ff1ddad7593361eaa449_20160921_e6771cfa2574_5037 {
  meta:
    description = "datamaliciousorder - from files 20160921_41f7b3abc606ff1ddad7593361eaa449.js, 20160921_e6771cfa257410eb61913de76cb777a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53e06a7234c6522ba26a61e46d13312e1063594b0e33bec9fae49d2dc4b77c28"
    hash2       = "009074e75815902f1e36daa21c179598b761767cd8d92eb363f3541838abdbfe"

  strings:
    $s1 = "){return \"Py\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"DAa\";}" ascii
    $s2 = " \"Na\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s3 = "})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck" ascii
    $s4 = " fuck(){return \"Nm\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IP" ascii
    $s5 = "Rn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Na\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}