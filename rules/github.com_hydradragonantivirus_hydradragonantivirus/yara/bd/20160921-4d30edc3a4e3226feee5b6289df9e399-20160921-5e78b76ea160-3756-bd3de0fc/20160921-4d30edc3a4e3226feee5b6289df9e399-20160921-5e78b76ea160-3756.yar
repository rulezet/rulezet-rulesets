rule _20160921_4d30edc3a4e3226feee5b6289df9e399_20160921_5e78b76ea160_3756 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d30edc3a4e3226feee5b6289df9e399.js, 20160921_5e78b76ea160d891abcb41db9983d51f.js, 20160921_eda7773555acd8e0be7f4e8bf6d0b010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"
    hash2       = "789149d5f226f5eb3642909acb465b5f94d946ee53a79d693b40f83359c4471f"
    hash3       = "af4e0a7c109ffa140c9db57a44bcd9c5d9b5a7c75daded0b422d2cec24c01c8b"

  strings:
    $s1 = "){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"ZWu\";" ascii
    $s2 = "\"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s3 = "\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii
    $s4 = "ZWu\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(functi" ascii
    $s5 = "return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jo\";})()" ascii
    $s6 = "fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}