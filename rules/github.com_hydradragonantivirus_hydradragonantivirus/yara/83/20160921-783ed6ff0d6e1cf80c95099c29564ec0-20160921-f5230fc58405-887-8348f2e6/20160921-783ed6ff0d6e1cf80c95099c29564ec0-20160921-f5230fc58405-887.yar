rule _20160921_783ed6ff0d6e1cf80c95099c29564ec0_20160921_f5230fc58405_887 {
  meta:
    description = "datamaliciousorder - from files 20160921_783ed6ff0d6e1cf80c95099c29564ec0.js, 20160921_f5230fc58405f25233bda6815654bd6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "91c59edb0e2a43b5780f865f87a5462b55dab1281045b0a38b38ac155b7d34b6"
    hash2       = "1a813dda7d0088c45bb00563ea79982995ec1337c805380117fe705f80c51c64"

  strings:
    $s1  = "ck(){return \"TTs\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"UOe" ascii
    $s2  = "tion fuck(){return \"Pc\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return " ascii
    $s3  = "function fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){r" ascii
    $s4  = ",(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){r" ascii
    $s5  = "fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Cd" ascii
    $s6  = "\"Bz\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"FJs\";})(),(funct" ascii
    $s7  = "\"Ug\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(funct" ascii
    $s8  = "(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Hs\";})" ascii
    $s9  = "ck(){return \"ZWu\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\"" ascii
    $s10 = ",(function fuck(){return \"Qh\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){" ascii
    $s11 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"" ascii
    $s12 = "fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GN" ascii
    $s13 = "eturn \"Ai\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s14 = "g\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(functio" ascii
    $s15 = "n fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"I" ascii
    $s16 = "urn \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"USf\";})()," ascii
    $s17 = "\"Cd\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(funct" ascii
    $s18 = "){return \"AUx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ZWu\";}" ascii
    $s19 = "\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function f" ascii
    $s20 = "n \"EHo\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}