rule _20160921_8f9ae4533bfbaedf1feae61032904250_20160921_cd62091b5494_2539 {
  meta:
    description = "datamaliciousorder - from files 20160921_8f9ae4533bfbaedf1feae61032904250.js, 20160921_cd62091b54940830ea3695d380fd97d8.js, 20160921_e354814fb0864710c25f5e3e9db82ed9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f093836b93b9b87ed10341ee30bc818ac497c91c6d0dd2b00ab5d3b1822868f9"
    hash2       = "e00553588533d1015b71812c5877864382cbfd2a3a204b4cab76c38ee65ce58c"
    hash3       = "404a4224fa8dcbc9877419bc0d572bd67181c29f5eb3b1cff437b90863907b45"

  strings:
    $s1 = "Rx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"DRx\";})(),(function" ascii
    $s2 = "{return \"Zy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Vb\";})()," ascii
    $s3 = "\"XCr\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"DRx\";})(),(funct" ascii
    $s4 = "rn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"MIl\";})(),(f" ascii
    $s5 = "unction fuck(){return \"DRx\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Py\";})(),(function fuck(){ret" ascii
    $s6 = "(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(" ascii
    $s7 = "ck(){return \"OQr\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"UOe\"" ascii
    $s8 = "tion fuck(){return \"PDf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}