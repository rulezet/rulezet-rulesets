rule _20160921_1410ebf3977c301b1220cbf20d031672_20160921_f7fa978ba93c_4458 {
  meta:
    description = "datamaliciousorder - from files 20160921_1410ebf3977c301b1220cbf20d031672.js, 20160921_f7fa978ba93ca4504da33fc02cbf7f53.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "bba6a8e474a809cf21b57641f08c798b1175b5bb510dcebc8d2284017c4579ab"
    hash2       = "8c8d20603b0870465254e9f226f52f020b5b1d986c61571e7a3097b32ea728e0"

  strings:
    $s1 = "return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Zy\";})()" ascii
    $s2 = "on fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return " ascii
    $s3 = "urn \"GJx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s4 = "ck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\"" ascii
    $s5 = "rn \"QTc\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}