rule _20160921_06a2269d96cb1baf9f03ef4c6c30379d_20160921_0ef3d27b58b6_4264 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a2269d96cb1baf9f03ef4c6c30379d.js, 20160921_0ef3d27b58b620506f1d1320d2937789.js, 20160921_9e9f1aaa0e051c856253652c93b64496.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4904b4c397fdf3727eb6ad96b4ffc136ba26b2026b71428beeb74eac91fb976c"
    hash2       = "5e3dd80c1e1b35ce856eadc159cc2a53dce2adf2f9207a618bd73679e9d868b7"
    hash3       = "150de993662365ce2c7407195d1e62da40d5d5ecc67a4a3eb34985123077ada3"

  strings:
    $s1 = "uck(){return \"DRx\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Jh\"" ascii
    $s2 = "n \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"Np\";})(),(fu" ascii
    $s3 = "unction fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){retu" ascii
    $s4 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return " ascii
    $s5 = "{return \"Jg\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}