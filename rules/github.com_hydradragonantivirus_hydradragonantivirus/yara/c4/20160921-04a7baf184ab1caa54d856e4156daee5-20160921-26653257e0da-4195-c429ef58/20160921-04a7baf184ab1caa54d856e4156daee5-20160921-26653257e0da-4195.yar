rule _20160921_04a7baf184ab1caa54d856e4156daee5_20160921_26653257e0da_4195 {
  meta:
    description = "datamaliciousorder - from files 20160921_04a7baf184ab1caa54d856e4156daee5.js, 20160921_26653257e0da59c861fc658d3bccdafd.js, 20160921_3a888f864f15e69e777cbaaa06f962e5.js, 20160921_7f6803f2f6f680d96e6355ff22eeb754.js, 20160921_c694815b18c140f34c0f79f86106d901.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "436cacbd20422493740457b774290fc75ea097813018720a8afa8162bb912052"
    hash2       = "1dff3cae9c135714cad3879ac1ef904841ec9264e3448106fbedd3b57ca11e97"
    hash3       = "65826487c59973db0339cbaf1f8e99201516dc26d5bdf1991855fafe9cbc5da1"
    hash4       = "90a92dcfba596004523ed3fa83de824553929a4a3723ce68cfae6d2394ad8394"
    hash5       = "650c20b763cdd9e1631c1f76f67b04a911cfce7996c1e9928b9c3b7fe1f8e7e5"

  strings:
    $s1 = "ction fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return" ascii
    $s2 = "\"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(fun" ascii
    $s3 = "return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s4 = "nction fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s5 = "fuck(){return \"TTs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"US" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}