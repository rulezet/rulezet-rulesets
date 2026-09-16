rule _20160921_1a47c8a8ea95b60eabaed27e984edacd_20160921_6fabf8ef6df7_4577 {
  meta:
    description = "datamaliciousorder - from files 20160921_1a47c8a8ea95b60eabaed27e984edacd.js, 20160921_6fabf8ef6df7ba14509fab6de95d721f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5a5f062c9d94508668ecb987b9d855fefbcdb1cf10f3efded37c21fc6893b0c"
    hash2       = "a6962383b3793edac58fef061128f9047afb39eaa645d3f7977a775ceeb02e56"

  strings:
    $s1 = ";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuc" ascii
    $s2 = "\"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"YQt\";})(),(func" ascii
    $s3 = ",(function fuck(){return \"Nm\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){r" ascii
    $s4 = "eturn \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})()," ascii
    $s5 = "k(){return \"Mw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}