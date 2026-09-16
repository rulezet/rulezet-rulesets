rule _20160921_b0c04db09e980eb82ccee9091ca50467_20160921_d414cec9501c_1745 {
  meta:
    description = "datamaliciousorder - from files 20160921_b0c04db09e980eb82ccee9091ca50467.js, 20160921_d414cec9501c17802073a2f8f7b005c4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9e020a4a8174eebc9bdfd2c370a1a8a86e255e968f9dc218329e9d5912ba227b"
    hash2       = "65e6cb34b6f46aaa1020cec9a648634a1eceb7e9d6ad0387fc939923e8236594"

  strings:
    $s1  = "n fuck(){return \"Cd\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"AD" ascii
    $s2  = "nction fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s3  = "n \"Wo\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s4  = "function fuck(){return \"Ot\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){ret" ascii
    $s5  = "ck(){return \"Oh\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"TTs\";" ascii
    $s6  = "})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s7  = "\"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Dc\";})(),(func" ascii
    $s8  = "urn \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"MUs\";})(),(" ascii
    $s9  = "ction fuck(){return \"Za\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return" ascii
    $s10 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ot\";})(),(function fuc" ascii
    $s11 = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}