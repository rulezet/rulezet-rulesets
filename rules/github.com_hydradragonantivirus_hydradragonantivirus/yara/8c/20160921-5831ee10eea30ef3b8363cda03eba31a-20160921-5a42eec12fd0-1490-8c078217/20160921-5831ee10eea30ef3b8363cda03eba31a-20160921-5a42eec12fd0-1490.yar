rule _20160921_5831ee10eea30ef3b8363cda03eba31a_20160921_5a42eec12fd0_1490 {
  meta:
    description = "datamaliciousorder - from files 20160921_5831ee10eea30ef3b8363cda03eba31a.js, 20160921_5a42eec12fd0d8c1d5256852068b87b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2249c045e34389dbbb9e3554dc23ae5207cc7f4205df2feaede6b0df279995cb"
    hash2       = "54a7451a184fd8afa3cac9d787d5f83abeb8fecd14d9f136cff135e9f0d849e0"

  strings:
    $s1  = "n fuck(){return \"KVh\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return " ascii
    $s2  = "\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(function" ascii
    $s3  = "return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(" ascii
    $s4  = "{return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Za\";})()" ascii
    $s5  = "(){return \"Hs\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"USf\";}" ascii
    $s6  = "){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Ai\";})" ascii
    $s7  = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Zy\";})()," ascii
    $s8  = ")(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IPu\";})(),(function fuc" ascii
    $s9  = "k(){return \"YQt\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"PDf\"" ascii
    $s10 = "Wo\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s11 = ")(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"YQt\";})(),(function fuck" ascii
    $s12 = "\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"KVh\";})(),(function " ascii
    $s13 = " \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Av\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}