rule _20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa_20160921_93920c7f8d8d_4683 {
  meta:
    description = "datamaliciousorder - from files 20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa.js, 20160921_93920c7f8d8dcef0135d270226e913f5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8753bd153b88da9a4351b5d6a0111d7af66a0f18e8b8a42beee11ad2916dc183"
    hash2       = "a340a8acce75472b10972c1d41244236fbd98f0f2ecd9effbe64bc76604b8eb6"

  strings:
    $s1 = "tion fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return " ascii
    $s2 = " \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(func" ascii
    $s3 = "){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})" ascii
    $s4 = "fuck(){return \"TTs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LG" ascii
    $s5 = " fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GN" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}