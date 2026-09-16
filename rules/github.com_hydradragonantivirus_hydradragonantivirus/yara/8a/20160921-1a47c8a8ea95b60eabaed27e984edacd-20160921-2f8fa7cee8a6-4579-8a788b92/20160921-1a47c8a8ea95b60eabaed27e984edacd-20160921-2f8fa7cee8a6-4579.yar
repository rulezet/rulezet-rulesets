rule _20160921_1a47c8a8ea95b60eabaed27e984edacd_20160921_2f8fa7cee8a6_4579 {
  meta:
    description = "datamaliciousorder - from files 20160921_1a47c8a8ea95b60eabaed27e984edacd.js, 20160921_2f8fa7cee8a6f4f78978b7417f3f700e.js, 20160921_d29f34806a7d94f2bbb7a733fc4c43bc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5a5f062c9d94508668ecb987b9d855fefbcdb1cf10f3efded37c21fc6893b0c"
    hash2       = "6410122a95cd840a4eef622389d8026475b4f6a156d4b5288cf227165c036c96"
    hash3       = "70ffc02d6ba6dee7d11e2b608cd1544f99d837ffc746455c17b70d5b07ba0ac9"

  strings:
    $s1 = "){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";}" ascii
    $s2 = "function fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){re" ascii
    $s3 = "ck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg" ascii
    $s4 = "eturn \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})()," ascii
    $s5 = ",(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}