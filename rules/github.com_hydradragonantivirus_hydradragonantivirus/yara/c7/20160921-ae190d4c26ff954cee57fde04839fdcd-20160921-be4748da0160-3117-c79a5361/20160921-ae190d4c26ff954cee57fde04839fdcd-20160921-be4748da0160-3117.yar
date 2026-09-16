rule _20160921_ae190d4c26ff954cee57fde04839fdcd_20160921_be4748da0160_3117 {
  meta:
    description = "datamaliciousorder - from files 20160921_ae190d4c26ff954cee57fde04839fdcd.js, 20160921_be4748da01602fdf2d9ffd03054028e4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a337ab3ebbd0c762482045ac2f2536c27fbe1276893efdedbafc2c805709064"
    hash2       = "4847889a558b3e0b60d671ec5082e36330f771c8789f9ae89683bf49e7128616"

  strings:
    $s1 = "n \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii
    $s2 = "ion fuck(){return \"MBg\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return " ascii
    $s3 = " fuck(){return \"OQr\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Y" ascii
    $s4 = ")(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GJx\";})(),(function fuck" ascii
    $s5 = "rn \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(" ascii
    $s6 = " fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"" ascii
    $s7 = "urn \"YAv\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}