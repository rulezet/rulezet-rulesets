rule _20160921_0344ac0ed807ef595e2aeca98d44f575_20160921_1a47c8a8ea95_4149 {
  meta:
    description = "datamaliciousorder - from files 20160921_0344ac0ed807ef595e2aeca98d44f575.js, 20160921_1a47c8a8ea95b60eabaed27e984edacd.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f631e328f07a7c3d34221081061f64d96da25c4f05169c427adb507bb6941f58"
    hash2       = "b5a5f062c9d94508668ecb987b9d855fefbcdb1cf10f3efded37c21fc6893b0c"

  strings:
    $s1 = "urn \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"AUx\";})(),(" ascii
    $s2 = "(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"AUx\";" ascii
    $s3 = "urn \"IPu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"FJs\";})()," ascii
    $s4 = "GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"AUx\";})(),(functi" ascii
    $s5 = "Ts\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"FJs\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}