rule _20160921_a84d89efd5400c906c1132a56b0ef679_20160921_e072f9d237d6_300 {
  meta:
    description = "datamaliciousorder - from files 20160921_a84d89efd5400c906c1132a56b0ef679.js, 20160921_e072f9d237d6a3b969fa334b2e277a33.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3cfecdabdf17d9af410d0fee7ec88844bc361668aca1a114832bd3e515d3456"
    hash2       = "6a03793a4e6175c2a80395cdedba1eaf5878722aa36c4cbfae104768ed79890d"

  strings:
    $s1  = "n \"IKv\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(f" ascii
    $s2  = " fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"" ascii
    $s3  = "),(function fuck(){return \"LGo\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(" ascii
    $s4  = "rn \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(fu" ascii
    $s5  = "(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck" ascii
    $s6  = "ion fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s7  = "ction fuck(){return \"ADy\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s8  = "ction fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){retu" ascii
    $s9  = "){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Cd\";}" ascii
    $s10 = "nction fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s11 = "rn \"Jo\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s12 = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return " ascii
    $s13 = "\"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(funct" ascii
    $s14 = "fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd" ascii
    $s15 = "})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"AUx\";})(),(function fuc" ascii
    $s16 = " \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(fun" ascii
    $s17 = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retur" ascii
    $s18 = "ion fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s19 = "ion fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return" ascii
    $s20 = "),(function fuck(){return \"OQr\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"XFd\";})(),(function fuck(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}