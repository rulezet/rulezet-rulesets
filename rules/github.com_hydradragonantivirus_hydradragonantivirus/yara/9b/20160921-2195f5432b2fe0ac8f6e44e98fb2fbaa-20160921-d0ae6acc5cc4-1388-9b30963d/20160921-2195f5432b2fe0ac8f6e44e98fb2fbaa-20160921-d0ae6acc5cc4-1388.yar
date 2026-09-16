rule _20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa_20160921_d0ae6acc5cc4_1388 {
  meta:
    description = "datamaliciousorder - from files 20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa.js, 20160921_d0ae6acc5cc4f52f8d5df0b47ef8659a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8753bd153b88da9a4351b5d6a0111d7af66a0f18e8b8a42beee11ad2916dc183"
    hash2       = "8cde265a6a44d9e9f86f351959c030a86800d101b5b5ca057ac1cdc5c5a1e38d"

  strings:
    $s1  = "n fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s2  = "(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function fuck" ascii
    $s3  = "\"IPu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(func" ascii
    $s4  = "Go\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(functio" ascii
    $s5  = "unction fuck(){return \"DHd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){re" ascii
    $s6  = "fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"H" ascii
    $s7  = "n fuck(){return \"IRn\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s8  = "ction fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retur" ascii
    $s9  = "n \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(fu" ascii
    $s10 = "n fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"" ascii
    $s11 = ",(function fuck(){return \"USf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck()" ascii
    $s12 = "ction fuck(){return \"CTm\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retur" ascii
    $s13 = "on fuck(){return \"Vb\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"" ascii
    $s14 = "n \"Ai\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Pc\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}