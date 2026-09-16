rule _20160921_099ae50c92fa9b72abe88204de915580_20160921_511769d99fbe_2677 {
  meta:
    description = "datamaliciousorder - from files 20160921_099ae50c92fa9b72abe88204de915580.js, 20160921_511769d99fbe4d59a2e55781fb0eb77c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "344e6822e369c3beb064ffee655d0ce0db901d1bada577cd8f338fc2aec06cb8"
    hash2       = "2f4a69b097fb3d0d29d7f041be11cd2e8af137bd0ed525674079a1b7de28c7fd"

  strings:
    $s1 = ")(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ve\";})(),(function fuck(" ascii
    $s2 = "ion fuck(){return \"Ar\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return " ascii
    $s3 = "\"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(func" ascii
    $s4 = "n fuck(){return \"OQr\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"" ascii
    $s5 = "uck(){return \"Dc\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Hs\"" ascii
    $s6 = "return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Ar\";})()" ascii
    $s7 = "rn \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"Fv\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}