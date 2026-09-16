rule _20160921_31c7951a9301bccac7c42ed2b6b13093_20160921_e2617d9e437c_331 {
  meta:
    description = "datamaliciousorder - from files 20160921_31c7951a9301bccac7c42ed2b6b13093.js, 20160921_e2617d9e437c12b61ada4700f8e426b8.js, 20160921_e354814fb0864710c25f5e3e9db82ed9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "170c53b6198c4ffe293d40953d3f705212182666ee02a10f7b562b4a16af7559"
    hash2       = "732b58fdcabccece6ef3ce710e7c0ba505cd66ea292afad6fac2c48739151b46"
    hash3       = "404a4224fa8dcbc9877419bc0d572bd67181c29f5eb3b1cff437b90863907b45"

  strings:
    $s1  = ",(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck()" ascii
    $s2  = "fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"C" ascii
    $s3  = ",(function fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){" ascii
    $s4  = "ion fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s5  = "nction fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s6  = "MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(functio" ascii
    $s7  = "return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(" ascii
    $s8  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return " ascii
    $s9  = "on fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s10 = "u\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function " ascii
    $s11 = "turn \"Np\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(" ascii
    $s12 = ")(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuc" ascii
    $s13 = "n \"IPu\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(fu" ascii
    $s14 = "nction fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){retu" ascii
    $s15 = "ion fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s16 = "ction fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return" ascii
    $s17 = "(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";" ascii
    $s18 = " \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(func" ascii
    $s19 = "ck(){return \"RAi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\"" ascii
    $s20 = "urn \"ADy\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}