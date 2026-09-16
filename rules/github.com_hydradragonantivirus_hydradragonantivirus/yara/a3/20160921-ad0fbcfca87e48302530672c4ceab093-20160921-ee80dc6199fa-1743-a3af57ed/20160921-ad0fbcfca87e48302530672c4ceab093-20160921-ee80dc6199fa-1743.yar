rule _20160921_ad0fbcfca87e48302530672c4ceab093_20160921_ee80dc6199fa_1743 {
  meta:
    description = "datamaliciousorder - from files 20160921_ad0fbcfca87e48302530672c4ceab093.js, 20160921_ee80dc6199fa2bd2aea50402a233f984.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "481451a3850055fd2d398d5707171f67d2aa3cd019214d6b67f539efc81ca7bb"
    hash2       = "b51d9165093e08385081a749ef6331a3556fe2739b6c8f85b62e7f6ec1b4f662"

  strings:
    $s1  = ";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"ADy\";})(),(function fu" ascii
    $s2  = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"XFd\";})" ascii
    $s3  = "i\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s4  = "),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MOj\";})(),(function fuck()" ascii
    $s5  = "DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(functi" ascii
    $s6  = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retu" ascii
    $s7  = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){retu" ascii
    $s8  = " fuck(){return \"MBg\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"MU" ascii
    $s9  = "(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"OPz\";" ascii
    $s10 = "ion fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return" ascii
    $s11 = "){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}