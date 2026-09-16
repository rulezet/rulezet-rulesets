rule _20160921_469953d9833167e141d9f086f1f41437_20160921_9dc96613aa4c_3717 {
  meta:
    description = "datamaliciousorder - from files 20160921_469953d9833167e141d9f086f1f41437.js, 20160921_9dc96613aa4c64f92e4ff218607f50d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "e29808d818b8f5ea60d0baa8d6c3284d3673878f7f4309c5981ced86dc40c5f1"
    hash2       = "f6c272b2491e06062a7ec30effe81ff00903e7c91b1be85625b1fe6794546c7a"

  strings:
    $s1 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){retu" ascii
    $s2 = "){return \"Vf\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"GNm\";})(" ascii
    $s3 = "fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"M" ascii
    $s4 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retur" ascii
    $s5 = "uck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug" ascii
    $s6 = "fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"U" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}