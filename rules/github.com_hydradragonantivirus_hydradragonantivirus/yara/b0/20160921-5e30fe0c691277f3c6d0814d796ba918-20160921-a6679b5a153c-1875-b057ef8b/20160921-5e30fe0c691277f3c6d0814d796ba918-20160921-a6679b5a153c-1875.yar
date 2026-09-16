rule _20160921_5e30fe0c691277f3c6d0814d796ba918_20160921_a6679b5a153c_1875 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e30fe0c691277f3c6d0814d796ba918.js, 20160921_a6679b5a153c4bb3f7cb9fe7c02dc710.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cac2594d8c0286d3110fd3705816d41052df49790da39881cedd79b8cb5c6ed"
    hash2       = "c54f97191e0c15791315cc1823b0fbce23679bebe5b1ce5c2b6b4895074c1121"

  strings:
    $s1  = "nction fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){retu" ascii
    $s2  = "tion fuck(){return \"Ug\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s3  = "ck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Hs\";" ascii
    $s4  = "{return \"Jg\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})" ascii
    $s5  = "on fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return " ascii
    $s6  = "\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"MIl\";})(),(function" ascii
    $s7  = "function fuck(){return \"Yk\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){ret" ascii
    $s8  = " \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Jg\";})(),(func" ascii
    $s9  = "fuck(){return \"TTs\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"UO" ascii
    $s10 = "n \"Cd\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}