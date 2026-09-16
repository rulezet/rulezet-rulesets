rule _20160921_3688778166acb8f4f21b3c1d67ada442_20160921_37c1eae8c734_4905 {
  meta:
    description = "datamaliciousorder - from files 20160921_3688778166acb8f4f21b3c1d67ada442.js, 20160921_37c1eae8c73482d7ccd62bb1c25f74b0.js, 20160921_64060d97e498db57bf68dbb08be86bba.js, 20160921_8c8c9fad8af659443108d1078847a668.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "03559b6095f398f17a62ec1f50c0a70c4b4074a67f6b8e3a51dfe026b238b085"
    hash2       = "8e724c0f7c8722eec82dd0f37b13b38ab5c357aeccb2cc6c36efae80bae66a8a"
    hash3       = "30a02b9f75ed0112affe2c698cfdbe2ec2a5bc4d8248ac34ebe13e072bd212f0"
    hash4       = "05c35ee4072476c50081705469d125bb2570dea942839cab58bf87874667da59"

  strings:
    $s1 = "on fuck(){return \"Zy\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s2 = "tion fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return" ascii
    $s3 = "unction fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s4 = "rn \"Np\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(fu" ascii
    $s5 = "return \"MBg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"IOs\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}