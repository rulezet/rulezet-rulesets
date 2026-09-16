rule _20160921_8b272d3350b65135770a56abfe6a28e0_20160921_c38068bdcf61_5525 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b272d3350b65135770a56abfe6a28e0.js, 20160921_c38068bdcf6149dc68d38cbcccfe991f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e33679bc8447125e30a6b07d53b91fb8c7307bd0acbe67f2f89665270647873e"
    hash2       = "d59dd40562ac50a453dbb7054114c62cfd7c63d24b81c776b35af40fb9aa3480"

  strings:
    $s1 = "){return \"GNm\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"QTc\";}" ascii
    $s2 = "function fuck(){return \"OQr\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){re" ascii
    $s3 = "ction fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fuck(){retur" ascii
    $s4 = "ZVi\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Sx\";})(),(functio" ascii
    $s5 = "{return \"ZLd\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}