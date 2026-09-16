rule _20160921_2a4687842acdb7843675f91c11ae7986_20160921_f69cc523f438_90 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4687842acdb7843675f91c11ae7986.js, 20160921_f69cc523f43841dbc6246209e09d2b8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b483b885082d284a148ab2a97b57881cd387b85b477025ad126d680e158bc62"
    hash2       = "82ee8104aecfd309a85de470b641e14f7ef67f3b3ec968ce41eade759620fd53"

  strings:
    $s1  = "k(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";}" ascii
    $s2  = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){retur" ascii
    $s3  = "),(function fuck(){return \"TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"XFd\";})(),(function fuck()" ascii
    $s4  = "turn \"Hs\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s5  = "fuck(){return \"TTs\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Y" ascii
    $s6  = "v\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jo\";})(),(function" ascii
    $s7  = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"CCb\";})(),(function fuck(" ascii
    $s8  = "),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){" ascii
    $s9  = "{return \"Wo\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s10 = "urn \"Ve\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"USf\";})(),(" ascii
    $s11 = "n fuck(){return \"YAv\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s12 = "k(){return \"AUx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"ADy" ascii
    $s13 = "on fuck(){return \"YQt\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s14 = "u\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DWe\";})(),(function" ascii
    $s15 = "function fuck(){return \"RAi\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){re" ascii
    $s16 = "urn \"Bz\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(fun" ascii
    $s17 = "uck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn" ascii
    $s18 = "urn \"Za\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s19 = ")(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Py\";})(),(function fuck(" ascii
    $s20 = "urn \"RAi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"UOe\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}