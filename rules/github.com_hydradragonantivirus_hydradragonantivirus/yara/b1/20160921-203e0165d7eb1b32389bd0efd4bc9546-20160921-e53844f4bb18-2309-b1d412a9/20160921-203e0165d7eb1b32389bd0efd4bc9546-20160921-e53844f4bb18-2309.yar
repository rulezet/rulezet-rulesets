rule _20160921_203e0165d7eb1b32389bd0efd4bc9546_20160921_e53844f4bb18_2309 {
  meta:
    description = "datamaliciousorder - from files 20160921_203e0165d7eb1b32389bd0efd4bc9546.js, 20160921_e53844f4bb18305322896332fbd017e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9112c30f4cc79af123a3f3e13b1e01a29f2419955988701cb25a673fdfe684d"
    hash2       = "b8484bab412a47fffb0a694f32ca5de3480841bd1c0806d0a7e6e86dfd21de6c"

  strings:
    $s1 = " \"Cd\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";})(),(func" ascii
    $s2 = "on fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s3 = "(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"XFd\";})(),(function fuck" ascii
    $s4 = "turn \"DRx\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"AUx\";})()," ascii
    $s5 = "})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"AUx\";})(),(function fuc" ascii
    $s6 = "n fuck(){return \"DRx\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"" ascii
    $s7 = "TTs\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Hs\";})(),(functio" ascii
    $s8 = "n fuck(){return \"We\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IP" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}