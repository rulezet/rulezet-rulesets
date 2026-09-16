rule _20160921_063094039ef79437a260d3dde960797a_20160921_e8d738510e4d_1324 {
  meta:
    description = "datamaliciousorder - from files 20160921_063094039ef79437a260d3dde960797a.js, 20160921_e8d738510e4d2e0efb6c7aa18a7a58d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1eb4a08b98ec71f6759f87657e36ddf82182025b3e317c586fb55c186b9e6c"
    hash2       = "e1cd4a36522d2ad8fc8435b6cb64d8e572d8b31d4203885fa375f539a3ea7891"

  strings:
    $s1  = "(function fuck(){return \"DHd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){r" ascii
    $s2  = "(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Hs\";})(),(function fuck()" ascii
    $s3  = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"" ascii
    $s4  = "\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"LGo\";})(),(function " ascii
    $s5  = "n fuck(){return \"Ar\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"" ascii
    $s6  = "fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IRn" ascii
    $s7  = "on fuck(){return \"We\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"P" ascii
    $s8  = "return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s9  = "ction fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retur" ascii
    $s10 = " \"CTm\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(func" ascii
    $s11 = "return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s12 = "n fuck(){return \"DAa\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"" ascii
    $s13 = "function fuck(){return \"Pc\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){ret" ascii
    $s14 = "turn \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(" ascii
    $s15 = "eturn \"LGo\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"NKq\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}