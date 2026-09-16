rule _20160921_c4701eeb8c1954cdca7ebff879af825b_20160921_ccb7f2594ec3_5680 {
  meta:
    description = "datamaliciousorder - from files 20160921_c4701eeb8c1954cdca7ebff879af825b.js, 20160921_ccb7f2594ec30d819d8973993796faf6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "434597ea9990301d4bb62f8905b136fc4a13b61d61fa5eeef5efdc7757f1f1bc"
    hash2       = "d05110dd6f0ccc6122f08dac231858be0e233eb3cfb596f5f571556d227ab3ef"

  strings:
    $s1 = " \"ZWu\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(func" ascii
    $s2 = "uck(){return \"CCb\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"IPu" ascii
    $s3 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){retur" ascii
    $s4 = "\"Jo\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s5 = "(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"We\";})(),(function fuck()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}