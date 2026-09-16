rule _20160921_962ed1e894cd91f421ad984310ce3140_20160921_ae190d4c26ff_3991 {
  meta:
    description = "datamaliciousorder - from files 20160921_962ed1e894cd91f421ad984310ce3140.js, 20160921_ae190d4c26ff954cee57fde04839fdcd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5ddab3f025feef0c562b4f7f707a08e5d6502c7b7178d3d6367d05bae0018033"
    hash2       = "0a337ab3ebbd0c762482045ac2f2536c27fbe1276893efdedbafc2c805709064"

  strings:
    $s1 = ";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function f" ascii
    $s2 = " \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii
    $s3 = "(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck" ascii
    $s4 = "u\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Na\";})(),(function " ascii
    $s5 = ";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function f" ascii
    $s6 = "\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}