rule _20160921_627f79d589bde52c443bc2d40f887ced_20160921_b0c04db09e98_1594 {
  meta:
    description = "datamaliciousorder - from files 20160921_627f79d589bde52c443bc2d40f887ced.js, 20160921_b0c04db09e980eb82ccee9091ca50467.js, 20160921_c779962dc8b38bbb280b695e631131fa.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f23a9d984b71a422ca30ec7f94f4a4cb0a2303699dc80edbced4a4c608e370e4"
    hash2       = "9e020a4a8174eebc9bdfd2c370a1a8a86e255e968f9dc218329e9d5912ba227b"
    hash3       = "cf3f9e3180d8fa16719dbea90d762850a1742512c7be6bc42325dc9e094add30"

  strings:
    $s1  = "fuck(){return \"MUs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQ" ascii
    $s2  = "ion fuck(){return \"Zy\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return " ascii
    $s3  = ",(function fuck(){return \"Ot\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){" ascii
    $s4  = ")(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ZLd\";})(),(function fuc" ascii
    $s5  = "k(){return \"Ik\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";" ascii
    $s6  = ")(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(" ascii
    $s7  = "ck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx" ascii
    $s8  = " \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s9  = "turn \"Ve\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(f" ascii
    $s10 = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retur" ascii
    $s11 = "n \"PDf\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"IRn\";})(),(fun" ascii
    $s12 = "function fuck(){return \"XCr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){r" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}