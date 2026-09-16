rule _20160921_04a7baf184ab1caa54d856e4156daee5_20160921_734133432b5c_4191 {
  meta:
    description = "datamaliciousorder - from files 20160921_04a7baf184ab1caa54d856e4156daee5.js, 20160921_734133432b5c6f9bde8604a5856b0226.js, 20160921_7f6803f2f6f680d96e6355ff22eeb754.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "436cacbd20422493740457b774290fc75ea097813018720a8afa8162bb912052"
    hash2       = "ae166a3e50bde57db63d39eeb168b02f14d45f281093c1420136eb1293fd87ef"
    hash3       = "90a92dcfba596004523ed3fa83de824553929a4a3723ce68cfae6d2394ad8394"

  strings:
    $s1 = "d\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function" ascii
    $s2 = "n \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XHj\";})(),(fu" ascii
    $s3 = "){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu\";}" ascii
    $s4 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){retu" ascii
    $s5 = "Mw\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}