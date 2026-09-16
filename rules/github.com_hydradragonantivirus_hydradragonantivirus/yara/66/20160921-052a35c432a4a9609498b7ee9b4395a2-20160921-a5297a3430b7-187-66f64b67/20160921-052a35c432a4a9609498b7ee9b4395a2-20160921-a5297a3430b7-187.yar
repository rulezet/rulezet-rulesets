rule _20160921_052a35c432a4a9609498b7ee9b4395a2_20160921_a5297a3430b7_187 {
  meta:
    description = "datamaliciousorder - from files 20160921_052a35c432a4a9609498b7ee9b4395a2.js, 20160921_a5297a3430b731f07a8b2bd532530907.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "209fd59dbb6143d03e0b3619c6d5cc33114cb8e3b4f252eb6d9da074e7636495"
    hash2       = "3cc34a5e206b8e31e54d9f96ede8214dea00b391969498f92170a493ebd7aa45"

  strings:
    $s1  = "fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UOe" ascii
    $s2  = "n \"Ai\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s3  = "p\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function" ascii
    $s4  = "turn \"CCb\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s5  = "function fuck(){return \"PDf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){r" ascii
    $s6  = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){ret" ascii
    $s7  = "return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s8  = "{return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"GWo\";}" ascii
    $s9  = "k(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Et\";}" ascii
    $s10 = "i\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Jo\";})(),(function" ascii
    $s11 = "n \"Xg\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(fu" ascii
    $s12 = ")(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(" ascii
    $s13 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Oh\";})(),(function fuc" ascii
    $s14 = "ction fuck(){return \"ZWu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return" ascii
    $s15 = " \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s16 = "on fuck(){return \"ZWu\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s17 = " \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s18 = "(){return \"MUs\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\"" ascii
    $s19 = " fuck(){return \"Xw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw" ascii
    $s20 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}