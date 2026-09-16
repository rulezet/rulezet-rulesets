rule _20160921_5e78b76ea160d891abcb41db9983d51f_20160921_a6679b5a153c_5262 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e78b76ea160d891abcb41db9983d51f.js, 20160921_a6679b5a153c4bb3f7cb9fe7c02dc710.js, 20160921_eda7773555acd8e0be7f4e8bf6d0b010.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "789149d5f226f5eb3642909acb465b5f94d946ee53a79d693b40f83359c4471f"
    hash2       = "c54f97191e0c15791315cc1823b0fbce23679bebe5b1ce5c2b6b4895074c1121"
    hash3       = "af4e0a7c109ffa140c9db57a44bcd9c5d9b5a7c75daded0b422d2cec24c01c8b"

  strings:
    $s1 = "ction fuck(){return \"TTs\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){retur" ascii
    $s2 = "ck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"UXf" ascii
    $s3 = "k(){return \"Bz\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})()];" fullword ascii
    $s4 = "function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){r" ascii
    $s5 = "return \"Xw\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}