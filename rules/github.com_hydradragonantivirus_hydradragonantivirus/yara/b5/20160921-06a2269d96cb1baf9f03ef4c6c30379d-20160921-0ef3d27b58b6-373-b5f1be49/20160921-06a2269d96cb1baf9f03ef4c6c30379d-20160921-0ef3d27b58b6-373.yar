rule _20160921_06a2269d96cb1baf9f03ef4c6c30379d_20160921_0ef3d27b58b6_373 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a2269d96cb1baf9f03ef4c6c30379d.js, 20160921_0ef3d27b58b620506f1d1320d2937789.js, 20160921_1b24f7151bebd3644ff0608076bd2de9.js, 20160921_42353ce257534ed06a8c73cebdde12dc.js, 20160921_64fd82bf037f1ee6b74269456349f2e6.js, 20160921_91424e3b4f105c156aa0fa6f22c2306f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4904b4c397fdf3727eb6ad96b4ffc136ba26b2026b71428beeb74eac91fb976c"
    hash2       = "5e3dd80c1e1b35ce856eadc159cc2a53dce2adf2f9207a618bd73679e9d868b7"
    hash3       = "33f3c9ce370f10b37d492f9d2cda8602f5d90eb1573205e1a4da03da8066ff45"
    hash4       = "68261e17878fc3b618b0fec34ae97fb6fea1090c52fff206192cb972d23b2b35"
    hash5       = "ba779a9cd5d48159c0b701ec2bc1832d098c0d5cf1f3a9429684810372bfa1b2"
    hash6       = "b4a035e38404ad09be99953980865cdbcda5dd05b664dff96722afb53b0c9e29"

  strings:
    $s1  = "return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})(" ascii
    $s2  = "){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Xw\";})" ascii
    $s3  = "fuck(){return \"Ik\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr" ascii
    $s4  = "m\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ve\";})(),(function " ascii
    $s5  = "b\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function " ascii
    $s6  = "tion fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return" ascii
    $s7  = "(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){r" ascii
    $s8  = "\"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s9  = "fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy" ascii
    $s10 = "ion fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s11 = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s12 = "rn \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii
    $s13 = "uck(){return \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"RAi" ascii
    $s14 = "s\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function" ascii
    $s15 = "{return \"LGo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})" ascii
    $s16 = "rn \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(fun" ascii
    $s17 = "k(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq" ascii
    $s18 = "rn \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(fu" ascii
    $s19 = " fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"" ascii
    $s20 = "nction fuck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}