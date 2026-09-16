rule _20160921_0344ac0ed807ef595e2aeca98d44f575_20160921_262709d34b47_1946 {
  meta:
    description = "datamaliciousorder - from files 20160921_0344ac0ed807ef595e2aeca98d44f575.js, 20160921_262709d34b477380050375a3b5b2833b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f631e328f07a7c3d34221081061f64d96da25c4f05169c427adb507bb6941f58"
    hash2       = "2738de24af2af834f5ce43b4e99137d47cd1993ec0b6dc3c1071deb99efcd62c"

  strings:
    $s1 = "n fuck(){return \"ZLd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"N" ascii
    $s2 = "){return \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})" ascii
    $s3 = "nction fuck(){return \"Ar\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){retu" ascii
    $s4 = "g\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})(),(function " ascii
    $s5 = ")(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Jg\";})(),(function fuck(" ascii
    $s6 = "unction fuck(){return \"Ik\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s7 = "})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MOj\";})(),(function fuc" ascii
    $s8 = "tion fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii
    $s9 = "DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"IOs\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}