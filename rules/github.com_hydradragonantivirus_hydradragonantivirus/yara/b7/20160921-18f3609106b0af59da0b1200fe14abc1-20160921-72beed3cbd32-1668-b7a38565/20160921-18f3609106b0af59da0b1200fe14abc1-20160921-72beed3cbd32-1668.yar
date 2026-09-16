rule _20160921_18f3609106b0af59da0b1200fe14abc1_20160921_72beed3cbd32_1668 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3609106b0af59da0b1200fe14abc1.js, 20160921_72beed3cbd321b62d224a35a01639682.js, 20160921_c4701eeb8c1954cdca7ebff879af825b.js, 20160921_e4c63c3b699efd2f5fe2739b016a938a.js, 20160921_f1bb498dcbb1f3aecbc35886be394f58.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95fb9e6292746461417b0e539747d500c780ad17cb775a9db031f77eaa53a3e2"
    hash2       = "ce3c3a93d2e5df0f850da4d79a5f697eaff66f1043058d62f80adad98b476839"
    hash3       = "434597ea9990301d4bb62f8905b136fc4a13b61d61fa5eeef5efdc7757f1f1bc"
    hash4       = "9d5d6c2986818649619806d890aad49cda8d0da47fe67f38388e5441a53382a0"
    hash5       = "486454370a5dac6af41bfda9ac339e37120334ce5f7c4319bd0f8e9df9514b44"

  strings:
    $s1  = "k(){return \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\"" ascii
    $s2  = "k(){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\"" ascii
    $s3  = "})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Np\";})(),(function fuc" ascii
    $s4  = "UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(functi" ascii
    $s5  = "ck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx" ascii
    $s6  = "m\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"GNm\";})(),(function" ascii
    $s7  = "return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})()" ascii
    $s8  = "fuck(){return \"Ar\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz" ascii
    $s9  = "),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"PDf\";})(),(function fuck(" ascii
    $s10 = "PDf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(functi" ascii
    $s11 = " fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"I" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}