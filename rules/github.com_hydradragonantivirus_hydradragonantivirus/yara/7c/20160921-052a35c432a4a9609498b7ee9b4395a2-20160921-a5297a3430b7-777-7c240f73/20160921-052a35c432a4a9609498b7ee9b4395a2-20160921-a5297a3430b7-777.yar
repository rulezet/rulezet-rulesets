rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_a5297a3430b7_777 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_a5297a3430b731f07a8b2bd532530907.js, 20160921_da8c18b9dd89b42c83c09338a42522db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"
    hash3       = "4541906a912293fb2fd3b2f0762e5641f73d401239307230b5fc4ae411a1c4f0"

  strings:
    $s1  = "rn \"XFd\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Vb\";})(),(fu" ascii
    $s2  = "{return \"EHo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii
    $s3  = "){return \"Ar\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Dc\";})(" ascii
    $s4  = " \"Ot\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s5  = "(){return \"GWo\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"UOe\";" ascii
    $s6  = "){return \"XCr\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Np\";}" ascii
    $s7  = "nction fuck(){return \"CCb\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s8  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){retu" ascii
    $s9  = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Ot\";})(),(function fuc" ascii
    $s10 = "n fuck(){return \"Et\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"I" ascii
    $s11 = "UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(functi" ascii
    $s12 = "e\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function " ascii
    $s13 = "\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(function" ascii
    $s14 = "on fuck(){return \"Mw\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Z" ascii
    $s15 = "tion fuck(){return \"KVh\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s16 = "Ho\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(functio" ascii
    $s17 = "Ld\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s18 = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Yk\";})(),(function" ascii
    $s19 = ",(function fuck(){return \"Jo\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){r" ascii
    $s20 = "function fuck(){return \"Nm\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}