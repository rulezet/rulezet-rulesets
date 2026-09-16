rule _20160921_93920c7f8d8dcef0135d270226e913f5_20160921_df51150cb497_3987 {
  meta:
    description = "datamaliciousorder - from files 20160921_93920c7f8d8dcef0135d270226e913f5.js, 20160921_df51150cb4977f20502f85bfda11d939.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a340a8acce75472b10972c1d41244236fbd98f0f2ecd9effbe64bc76604b8eb6"
    hash2       = "81cf54f681cedb1b59ee2e355f226c046ac83c55ad32ce5241949279bb194bf1"

  strings:
    $s1 = "fuck(){return \"RAi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MB" ascii
    $s2 = "\"To\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s3 = " \"FJs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(fu" ascii
    $s4 = "Zy\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IRn\";})(),(functio" ascii
    $s5 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"G" ascii
    $s6 = "ck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"UXf" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}