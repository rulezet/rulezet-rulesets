rule _20160921_3a2902eaca0b2b91120958418b46c844_20160921_d82f64233994_998 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a2902eaca0b2b91120958418b46c844.js, 20160921_d82f642339947ac5ef4d322534d8cd70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "063bab1922376d926db97bdcd4342c2e9b0f2ec98d9fad81c2a3f86537c82b07"
    hash2       = "1af101b4afb2b8d290446a4841d803e88cb42849fb95f0cea056677487805eb6"

  strings:
    $s1  = "(){return \"Cd\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"DRx\";" ascii
    $s2  = "(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";}" ascii
    $s3  = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return " ascii
    $s4  = "nction fuck(){return \"ZWu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){retu" ascii
    $s5  = "fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DH" ascii
    $s6  = " fuck(){return \"UOe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"" ascii
    $s7  = ")(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jo\";})(),(function fuck" ascii
    $s8  = "),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){" ascii
    $s9  = "\"Hs\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(funct" ascii
    $s10 = "){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"GWo\";})" ascii
    $s11 = "urn \"Oh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(f" ascii
    $s12 = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"PDf\";})(),(funct" ascii
    $s13 = "eturn \"MBg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})()" ascii
    $s14 = "rn \"Jg\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(f" ascii
    $s15 = "){return \"Pc\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(" ascii
    $s16 = "{return \"Qh\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s17 = " \"Et\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"DRx\";})(),(funct" ascii
    $s18 = "\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IRn\";})(),(function f" ascii
    $s19 = "ion fuck(){return \"XFd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}