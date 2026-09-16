rule _20160921_2b38530ecae3735e98453e56dd7a0292_20160921_3d83b7982fc5_3568 {
  meta:
    description = "datamaliciousorder - from files 20160921_2b38530ecae3735e98453e56dd7a0292.js, 20160921_3d83b7982fc59266194f048e87fb066d.js, 20160921_d7a1651fca7129364bbe9da7195a89dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46f1595f803e301ed13d99315b244aac664f908c0c0d8ab508c1d104bf7ae947"
    hash2       = "f14778492463eaa86aec448221dcd9e88defb1f42404b2b80d42b0d0c41ffa66"
    hash3       = "2c37b7e410e05a2e285f2d4909012cdefffdcc0d9e06b06aafce7aba5b9684f6"

  strings:
    $s1 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return" ascii
    $s2 = ";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Vb\";})(),(function fuck" ascii
    $s3 = ";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fu" ascii
    $s4 = "{return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"AUx\";})" ascii
    $s5 = "eturn \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"XFd\";})(" ascii
    $s6 = " fuck(){return \"Cd\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NK" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}