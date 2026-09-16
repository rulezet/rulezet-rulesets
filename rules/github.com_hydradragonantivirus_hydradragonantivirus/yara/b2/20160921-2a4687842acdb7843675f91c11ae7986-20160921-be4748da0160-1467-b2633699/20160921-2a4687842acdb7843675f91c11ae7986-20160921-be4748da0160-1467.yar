rule _20160921_2a4687842acdb7843675f91c11ae7986_20160921_be4748da0160_1467 {
  meta:
    description = "datamaliciousorder - from files 20160921_2a4687842acdb7843675f91c11ae7986.js, 20160921_be4748da01602fdf2d9ffd03054028e4.js, 20160921_f69cc523f43841dbc6246209e09d2b8b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b483b885082d284a148ab2a97b57881cd387b85b477025ad126d680e158bc62"
    hash2       = "4847889a558b3e0b60d671ec5082e36330f771c8789f9ae89683bf49e7128616"
    hash3       = "82ee8104aecfd309a85de470b641e14f7ef67f3b3ec968ce41eade759620fd53"

  strings:
    $s1  = " fuck(){return \"DAa\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"" ascii
    $s2  = "\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"XHj\";})(),(function " ascii
    $s3  = "on fuck(){return \"Fv\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"" ascii
    $s4  = "unction fuck(){return \"DRx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){retu" ascii
    $s5  = ";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Sx\";})(),(function fuck" ascii
    $s6  = "rn \"QTc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(f" ascii
    $s7  = " \"ZLd\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii
    $s8  = "return \"GWo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"MIl\";})" ascii
    $s9  = "),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"ZWu\";})(),(function fuck()" ascii
    $s10 = ")(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Nm\";})(),(function fuck(" ascii
    $s11 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii
    $s12 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IP" ascii
    $s13 = "uck(){return \"OQr\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Dc\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}