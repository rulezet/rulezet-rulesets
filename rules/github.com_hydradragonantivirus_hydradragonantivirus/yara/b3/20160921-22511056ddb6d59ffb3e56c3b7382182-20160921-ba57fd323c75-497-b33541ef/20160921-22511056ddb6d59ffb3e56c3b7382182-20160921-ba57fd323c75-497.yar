rule _20160921_22511056ddb6d59ffb3e56c3b7382182_20160921_ba57fd323c75_497 {
  meta:
    description = "datamaliciousorder - from files 20160921_22511056ddb6d59ffb3e56c3b7382182.js, 20160921_ba57fd323c757d83bd9bb08cdba3b4a4.js, 20160921_c38068bdcf6149dc68d38cbcccfe991f.js, 20160921_efc4e68608b4bd36f7e16eb4722b21c6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1a5f7b2bfdf24defc0d363114441d0c0a0452fd599bf21d359b1b5f068dfc567"
    hash2       = "119b312aafd59cd12991442685e391e8850e3417b81d4aa79ae8e5c89a75f170"
    hash3       = "d59dd40562ac50a453dbb7054114c62cfd7c63d24b81c776b35af40fb9aa3480"
    hash4       = "fe50eec4105613d48ac273c2d63a5b952098f339f7f06871b77053c43642dba7"

  strings:
    $s1  = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){retur" ascii
    $s2  = "ction fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){retur" ascii
    $s3  = "urn \"Py\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s4  = "fuck(){return \"Pc\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Xw\"" ascii
    $s5  = "o\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Fv\";})(),(function f" ascii
    $s6  = "a\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ar\";})(),(function " ascii
    $s7  = "(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){ret" ascii
    $s8  = "function fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){retu" ascii
    $s9  = "nction fuck(){return \"LLv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){retu" ascii
    $s10 = "{return \"Xw\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"SUi\";})(" ascii
    $s11 = "{return \"Xg\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s12 = ";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Xw\";})(),(function fuck" ascii
    $s13 = "\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Hs\";})(),(function f" ascii
    $s14 = " fuck(){return \"Jg\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xg" ascii
    $s15 = "uck(){return \"LLv\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"Wn\";})(),(function fuck(){return \"XHj" ascii
    $s16 = ")(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(" ascii
    $s17 = "turn \"To\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Fv\";})(),(fu" ascii
    $s18 = "a\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"ZWu\";})(),(function" ascii
    $s19 = "),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){" ascii
    $s20 = "rn \"Za\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}