rule _20160921_67db5ecea174c85a1df44685d8781acd_20160921_bad084fc8365_92 {
  meta:
    description = "datamaliciousorder - from files 20160921_67db5ecea174c85a1df44685d8781acd.js, 20160921_bad084fc8365d25463811ce32bf91ceb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "240705f58012306a07f93042172cd93e3bba16b8c9e0a9dd928f169ce059bf22"
    hash2       = "047a9508e8bdaf65bc39b28d9eac8b287b7a434a3a0808290117a7b71d1d03f6"

  strings:
    $s1  = "})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Xw\";})(),(function fuck(" ascii
    $s2  = "tion fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return " ascii
    $s3  = "k(){return \"TTs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"SUi\";" ascii
    $s4  = "rn \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s5  = "urn \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XHj\";})(),(" ascii
    $s6  = "Pu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(function" ascii
    $s7  = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){ret" ascii
    $s8  = "\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Py\";})(),(function f" ascii
    $s9  = " \"Py\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s10 = "unction fuck(){return \"Xw\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s11 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return " ascii
    $s12 = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"ZLd\";})(),(functi" ascii
    $s13 = "(function fuck(){return \"Qh\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Py\";})(),(function fuck(){re" ascii
    $s14 = "tion fuck(){return \"IRn\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s15 = "tion fuck(){return \"We\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return" ascii
    $s16 = "){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})" ascii
    $s17 = "urn \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})(),(" ascii
    $s18 = "nction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){retu" ascii
    $s19 = "v\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"RAi\";})(),(function" ascii
    $s20 = "function fuck(){return \"USf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Py\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}