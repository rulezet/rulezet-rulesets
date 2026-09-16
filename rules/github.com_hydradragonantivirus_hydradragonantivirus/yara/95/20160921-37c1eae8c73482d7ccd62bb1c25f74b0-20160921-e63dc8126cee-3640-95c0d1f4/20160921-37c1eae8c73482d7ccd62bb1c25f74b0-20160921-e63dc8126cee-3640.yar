rule _20160921_37c1eae8c73482d7ccd62bb1c25f74b0_20160921_e63dc8126cee_3640 {
  meta:
    description = "datamaliciousorder - from files 20160921_37c1eae8c73482d7ccd62bb1c25f74b0.js, 20160921_e63dc8126cee826e8d941c1665ea92b4.js, 20160921_f5230fc58405f25233bda6815654bd6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8e724c0f7c8722eec82dd0f37b13b38ab5c357aeccb2cc6c36efae80bae66a8a"
    hash2       = "b87ae77185b5925bd9480daa9d4b74b2291cc670108bf85e0379579434ebff34"
    hash3       = "1a813dda7d0088c45bb00563ea79982995ec1337c805380117fe705f80c51c64"

  strings:
    $s1 = "rn \"Ug\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s2 = "Wo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(functio" ascii
    $s3 = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Dc\"" ascii
    $s4 = "fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GN" ascii
    $s5 = "ction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return" ascii
    $s6 = "rn \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Sx\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}