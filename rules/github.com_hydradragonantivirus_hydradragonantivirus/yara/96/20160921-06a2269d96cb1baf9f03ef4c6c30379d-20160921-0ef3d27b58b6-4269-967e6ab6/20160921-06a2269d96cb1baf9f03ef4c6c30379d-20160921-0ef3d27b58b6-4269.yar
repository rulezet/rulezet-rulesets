rule _20160921_06a2269d96cb1baf9f03ef4c6c30379d_20160921_0ef3d27b58b6_4269 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a2269d96cb1baf9f03ef4c6c30379d.js, 20160921_0ef3d27b58b620506f1d1320d2937789.js, 20160921_2c106cc001daa2dffdfde7e2aa5c908b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4904b4c397fdf3727eb6ad96b4ffc136ba26b2026b71428beeb74eac91fb976c"
    hash2       = "5e3dd80c1e1b35ce856eadc159cc2a53dce2adf2f9207a618bd73679e9d868b7"
    hash3       = "ca5356b92abf859d45d843749f45e5e06c7d045b4e7ea5d215ab87cdb8c8f66b"

  strings:
    $s1 = "return \"Jh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"GJx\";})()," ascii
    $s2 = "ck(){return \"Sx\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\"" ascii
    $s3 = "Fv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Mw\";})(),(function " ascii
    $s4 = "unction fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){ret" ascii
    $s5 = "n fuck(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQ" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}