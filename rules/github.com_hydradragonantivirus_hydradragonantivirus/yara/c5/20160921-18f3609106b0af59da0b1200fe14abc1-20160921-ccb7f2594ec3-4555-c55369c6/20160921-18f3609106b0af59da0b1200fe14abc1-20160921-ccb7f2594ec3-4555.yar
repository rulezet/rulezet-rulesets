rule _20160921_18f3609106b0af59da0b1200fe14abc1_20160921_ccb7f2594ec3_4555 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3609106b0af59da0b1200fe14abc1.js, 20160921_ccb7f2594ec30d819d8973993796faf6.js, 20160921_e4c63c3b699efd2f5fe2739b016a938a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95fb9e6292746461417b0e539747d500c780ad17cb775a9db031f77eaa53a3e2"
    hash2       = "d05110dd6f0ccc6122f08dac231858be0e233eb3cfb596f5f571556d227ab3ef"
    hash3       = "9d5d6c2986818649619806d890aad49cda8d0da47fe67f38388e5441a53382a0"

  strings:
    $s1 = "ion fuck(){return \"Pc\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"" ascii
    $s2 = "return \"UOe\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"MOj\";})()" ascii
    $s3 = "IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(functio" ascii
    $s4 = "(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){" ascii
    $s5 = "})(),(function fuck(){return \"QTc\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Xw\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}