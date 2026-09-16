rule _20160921_75e390c1072ba7a2cace860dd09909b9_20160921_bf6b3f12d2bf_137 {
  meta:
    description = "datamaliciousorder - from files 20160921_75e390c1072ba7a2cace860dd09909b9.js, 20160921_bf6b3f12d2bf727319a9cd8aa9a170cc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0de804f026f55adb786d09f07b7f96808213c0d0809b41d659332d25a2645536"
    hash2       = "6ff891fcf6c12c36bf13bc65b82adbb923eb443ffdabd587f48e44c93323b786"

  strings:
    $s1  = "nction fuck(){return \"FJs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s2  = "turn \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(f" ascii
    $s3  = "uck(){return \"Ug\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\"" ascii
    $s4  = "(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(function fuck" ascii
    $s5  = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Cd\";})(),(function fuc" ascii
    $s6  = "function fuck(){return \"Av\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){re" ascii
    $s7  = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"" ascii
    $s8  = "uck(){return \"Cd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MOj" ascii
    $s9  = "tion fuck(){return \"OQr\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return" ascii
    $s10 = "\"Xw\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(functi" ascii
    $s11 = "u\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"Vb\";})(),(function f" ascii
    $s12 = "\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"OPz\";})(),(function f" ascii
    $s13 = ";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"KVh\";})(),(function fuc" ascii
    $s14 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return" ascii
    $s15 = "rn \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ug\";})(),(fu" ascii
    $s16 = "nction fuck(){return \"Xw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return" ascii
    $s17 = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MOj\";})(),(function fuc" ascii
    $s18 = "rn \"DAa\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Ik\";})(),(f" ascii
    $s19 = "){return \"LLv\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Vf\";}" ascii
    $s20 = "){return \"Et\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"MOj\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}