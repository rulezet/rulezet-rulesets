rule _20160921_04a7baf184ab1caa54d856e4156daee5_20160921_1410ebf3977c_4196 {
  meta:
    description = "datamaliciousorder - from files 20160921_04a7baf184ab1caa54d856e4156daee5.js, 20160921_1410ebf3977c301b1220cbf20d031672.js, 20160921_734133432b5c6f9bde8604a5856b0226.js, 20160921_7f6803f2f6f680d96e6355ff22eeb754.js, 20160921_d905978b34bea5948e843dd7ecb9dc6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "436cacbd20422493740457b774290fc75ea097813018720a8afa8162bb912052"
    hash2       = "bba6a8e474a809cf21b57641f08c798b1175b5bb510dcebc8d2284017c4579ab"
    hash3       = "ae166a3e50bde57db63d39eeb168b02f14d45f281093c1420136eb1293fd87ef"
    hash4       = "90a92dcfba596004523ed3fa83de824553929a4a3723ce68cfae6d2394ad8394"
    hash5       = "8110e9072a75f1960f23243cc11d3c233a350d63360d8006cad608a2fb81e0b3"

  strings:
    $s1 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return " ascii
    $s2 = "n fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return " ascii
    $s3 = "})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"QTc\";})(),(function fuc" ascii
    $s4 = "{return \"OQr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"ZVi\";})" ascii
    $s5 = "turn \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}