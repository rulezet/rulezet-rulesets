rule _20160921_884f773b3c246c835029fc91499fb017_20160921_a6679b5a153c_3075 {
  meta:
    description = "datamaliciousorder - from files 20160921_884f773b3c246c835029fc91499fb017.js, 20160921_a6679b5a153c4bb3f7cb9fe7c02dc710.js, 20160921_ad0fbcfca87e48302530672c4ceab093.js, 20160921_e63dc8126cee826e8d941c1665ea92b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4523d83a689974fc97f79b6c7c440d4b9f2a13825d1b664954798d786c1e2609"
    hash2       = "c54f97191e0c15791315cc1823b0fbce23679bebe5b1ce5c2b6b4895074c1121"
    hash3       = "481451a3850055fd2d398d5707171f67d2aa3cd019214d6b67f539efc81ca7bb"
    hash4       = "b87ae77185b5925bd9480daa9d4b74b2291cc670108bf85e0379579434ebff34"

  strings:
    $s1 = "turn \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s2 = "o\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s3 = " \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s4 = ",(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){" ascii
    $s5 = "ction fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return" ascii
    $s6 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii
    $s7 = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}