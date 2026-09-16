rule _20160921_2a4687842acdb7843675f91c11ae7986_20160921_ede755ec6df0_229 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4687842acdb7843675f91c11ae7986.js, 20160921_ede755ec6df0951d79fb3f792a6b28b8.js, 20160921_f69cc523f43841dbc6246209e09d2b8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b483b885082d284a148ab2a97b57881cd387b85b477025ad126d680e158bc62"
    hash2       = "24831eade0fe1d3e87c174bc2c80b113a66f4b5da6235749feba09a377913e7a"
    hash3       = "82ee8104aecfd309a85de470b641e14f7ef67f3b3ec968ce41eade759620fd53"

  strings:
    $s1  = "n fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s2  = "on fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return " ascii
    $s3  = "on fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"" ascii
    $s4  = "\"AUx\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(fun" ascii
    $s5  = "uck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IRn" ascii
    $s6  = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"" ascii
    $s7  = "tion fuck(){return \"AUx\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retur" ascii
    $s8  = "\"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(funct" ascii
    $s9  = " \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s10 = "turn \"Yk\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s11 = "n \"UOe\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(f" ascii
    $s12 = "on fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return " ascii
    $s13 = "unction fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){re" ascii
    $s14 = "eturn \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"ADy\";})(" ascii
    $s15 = " fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"" ascii
    $s16 = "rn \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(" ascii
    $s17 = "{return \"Dc\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"RAi\";})" ascii
    $s18 = "n fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return " ascii
    $s19 = "n \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii
    $s20 = "k(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}