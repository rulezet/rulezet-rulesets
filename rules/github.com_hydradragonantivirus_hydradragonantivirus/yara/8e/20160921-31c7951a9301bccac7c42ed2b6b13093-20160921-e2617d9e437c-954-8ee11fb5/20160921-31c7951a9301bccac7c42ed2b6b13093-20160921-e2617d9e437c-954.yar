rule _20160921_31c7951a9301bccac7c42ed2b6b13093_20160921_e2617d9e437c_954 {
  meta:
    description = "datamaliciousorder - from files 20160921_31c7951a9301bccac7c42ed2b6b13093.js, 20160921_e2617d9e437c12b61ada4700f8e426b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "170c53b6198c4ffe293d40953d3f705212182666ee02a10f7b562b4a16af7559"
    hash2       = "732b58fdcabccece6ef3ce710e7c0ba505cd66ea292afad6fac2c48739151b46"

  strings:
    $s1  = "urn \"MBg\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s2  = " \"Ar\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s3  = "(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"GNm\";}" ascii
    $s4  = "rn \"Vf\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(f" ascii
    $s5  = "nction fuck(){return \"Ve\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){retu" ascii
    $s6  = "ction fuck(){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){retur" ascii
    $s7  = "{return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})" ascii
    $s8  = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Na\";" ascii
    $s9  = "urn \"TTs\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s10 = "Fd\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"USf\";})(),(function" ascii
    $s11 = "function fuck(){return \"ZLd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){r" ascii
    $s12 = "function fuck(){return \"DWe\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){re" ascii
    $s13 = "\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function " ascii
    $s14 = "Dy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Ik\";})(),(functio" ascii
    $s15 = "OQr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(functi" ascii
    $s16 = "uck(){return \"CCb\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"IPu" ascii
    $s17 = "n \"Zy\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s18 = "(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"IRn\";})(),(function fuck" ascii
    $s19 = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"" ascii
    $s20 = ",(function fuck(){return \"TTs\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}