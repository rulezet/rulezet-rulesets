rule _20160921_3d83b7982fc59266194f048e87fb066d_20160921_b0c04db09e98_1709 {
  meta:
    description = "datamaliciousorder - from files 20160921_3d83b7982fc59266194f048e87fb066d.js, 20160921_b0c04db09e980eb82ccee9091ca50467.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f14778492463eaa86aec448221dcd9e88defb1f42404b2b80d42b0d0c41ffa66"
    hash2       = "9e020a4a8174eebc9bdfd2c370a1a8a86e255e968f9dc218329e9d5912ba227b"

  strings:
    $s1  = "fuck(){return \"Py\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi" ascii
    $s2  = "return \"XHj\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Py\";})(" ascii
    $s3  = "turn \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"SUi\";})()," ascii
    $s4  = "})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"ZWu\";})(),(function fuc" ascii
    $s5  = "eturn \"ZWu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Np\";})(),(" ascii
    $s6  = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Ai\"" ascii
    $s7  = "unction fuck(){return \"SUi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){ret" ascii
    $s8  = "fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Fv" ascii
    $s9  = "(){return \"GJx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";}" ascii
    $s10 = "unction fuck(){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){ret" ascii
    $s11 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}