rule _20160921_072d194212f8a9a2728f7fb6d5953933_20160921_52f9b0fa9588_4285 {
  meta:
    description = "datamaliciousorder - from files 20160921_072d194212f8a9a2728f7fb6d5953933.js, 20160921_52f9b0fa9588abb39dc8ffa331cd277b.js, 20160921_67db5ecea174c85a1df44685d8781acd.js, 20160921_bad084fc8365d25463811ce32bf91ceb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73c215f339e3128df4a73ba4ad5b1db80d6620de77bd285fef1d86107197eace"
    hash2       = "7a84827d35b2b189a2872cc9d16d3ab675e3ec50c203690e75cf66ab54056731"
    hash3       = "240705f58012306a07f93042172cd93e3bba16b8c9e0a9dd928f169ce059bf22"
    hash4       = "047a9508e8bdaf65bc39b28d9eac8b287b7a434a3a0808290117a7b71d1d03f6"

  strings:
    $s1 = " \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Np\";})(),(fun" ascii
    $s2 = "return \"Jg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s3 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return " ascii
    $s4 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){retur" ascii
    $s5 = "ck(){return \"DRx\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Jh\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}