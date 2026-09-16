rule _20160921_1bb9bdcf05b8f8acd28d5286e804d5cc_20160921_67db5ecea174_4592 {
  meta:
    description = "datamaliciousorder - from files 20160921_1bb9bdcf05b8f8acd28d5286e804d5cc.js, 20160921_67db5ecea174c85a1df44685d8781acd.js, 20160921_bad084fc8365d25463811ce32bf91ceb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3937dec3a8d946e214facedccfe7f35e65dbd446a77d077a09996638d7524444"
    hash2       = "240705f58012306a07f93042172cd93e3bba16b8c9e0a9dd928f169ce059bf22"
    hash3       = "047a9508e8bdaf65bc39b28d9eac8b287b7a434a3a0808290117a7b71d1d03f6"

  strings:
    $s1 = "eturn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"YAv\";})()" ascii
    $s2 = "n fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"" ascii
    $s3 = "){return \"ILp\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"ILp\";}" ascii
    $s4 = "tion fuck(){return \"ZVi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return " ascii
    $s5 = "a\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"GWo\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}