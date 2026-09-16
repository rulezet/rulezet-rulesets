rule _20160921_3ec558d1fbbb49dae502fbac7c879ad5_20160921_910cd79d8583_101 {
  meta:
    description = "datamaliciousorder - from files 20160921_3ec558d1fbbb49dae502fbac7c879ad5.js, 20160921_910cd79d8583d0c6c23bd93547d341fd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "71f652a0e52aa70fe3179b7e90dff8ba55b85022fbfe5d5d2db1bf6f32a04513"
    hash2       = "77a08a00002fdf0cdac8ee96f3ed542c8dcd2c5851f8c2feec648c8adedf7468"

  strings:
    $s1  = "urn \"IKv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"RAi\";})(),(" ascii
    $s2  = "urn \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"QTc\";})(),(f" ascii
    $s3  = "ck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";" ascii
    $s4  = "urn \"Xw\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Xw\";})(),(fu" ascii
    $s5  = "i\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Ai\";})(),(function" ascii
    $s6  = "n fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"E" ascii
    $s7  = "ion fuck(){return \"Cd\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s8  = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ot\";})()," ascii
    $s9  = "ck(){return \"Ai\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})(),(function fuck(){return \"IPu\"" ascii
    $s10 = " \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(func" ascii
    $s11 = "uck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Ai" ascii
    $s12 = "})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Ai\";})(),(function fuc" ascii
    $s13 = "Pu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"MUs\";})(),(function" ascii
    $s14 = "(function fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){re" ascii
    $s15 = "n fuck(){return \"MBg\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"I" ascii
    $s16 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){ret" ascii
    $s17 = "o\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"UOe\";})(),(function " ascii
    $s18 = "\"Wo0\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(fun" ascii
    $s19 = "urn \"LGo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Fv\";})(),(f" ascii
    $s20 = "IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}