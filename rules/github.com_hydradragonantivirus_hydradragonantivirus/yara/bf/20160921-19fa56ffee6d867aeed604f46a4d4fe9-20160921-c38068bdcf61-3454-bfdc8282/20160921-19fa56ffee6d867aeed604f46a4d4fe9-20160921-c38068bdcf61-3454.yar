rule _20160921_19fa56ffee6d867aeed604f46a4d4fe9_20160921_c38068bdcf61_3454 {
  meta:
    description = "datamaliciousorder - from files 20160921_19fa56ffee6d867aeed604f46a4d4fe9.js, 20160921_c38068bdcf6149dc68d38cbcccfe991f.js, 20160921_eb528bac8085eeec9ca6760c41b0a818.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "988e83dedf7c32629210ef0407bb0e576898ac66d605c942d70e189051f472fd"
    hash2       = "d59dd40562ac50a453dbb7054114c62cfd7c63d24b81c776b35af40fb9aa3480"
    hash3       = "cde7bce07f038dbcc12ab3207be0245adc184f6540d425dd1ec837861c3e4440"

  strings:
    $s1 = "b\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"UOe\";})(),(functio" ascii
    $s2 = "on fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s3 = "n fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s4 = "(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\"" ascii
    $s5 = "ction fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retur" ascii
    $s6 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}