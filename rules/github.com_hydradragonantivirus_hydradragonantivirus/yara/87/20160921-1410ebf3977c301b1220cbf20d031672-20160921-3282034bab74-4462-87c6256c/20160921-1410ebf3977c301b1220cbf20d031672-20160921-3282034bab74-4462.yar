rule _20160921_1410ebf3977c301b1220cbf20d031672_20160921_3282034bab74_4462 {
  meta:
    description = "datamaliciousorder - from files 20160921_1410ebf3977c301b1220cbf20d031672.js, 20160921_3282034bab74b3776acf585e8adfca92.js, 20160921_e354814fb0864710c25f5e3e9db82ed9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bba6a8e474a809cf21b57641f08c798b1175b5bb510dcebc8d2284017c4579ab"
    hash2       = "0b99efa289490e150d7af72ae3e0fb067880b4a22c16ba75dec34f9945b5c2df"
    hash3       = "404a4224fa8dcbc9877419bc0d572bd67181c29f5eb3b1cff437b90863907b45"

  strings:
    $s1 = "ck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DHd" ascii
    $s2 = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return " ascii
    $s3 = "\"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(fun" ascii
    $s4 = "function fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){ret" ascii
    $s5 = "eturn \"TTs\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IPu\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}