rule _20160921_05c83a67fb56c3e2f515dcdc094f3438_20160921_1a0cb65a30f2_4240 {
  meta:
    description = "datamaliciousorder - from files 20160921_05c83a67fb56c3e2f515dcdc094f3438.js, 20160921_1a0cb65a30f2e052b2abb4edb6b853f4.js, 20160921_a8c002f684df9aec957f2a082ed80d84.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0535a055f646391a67e495ab3466f375b47d00382cf1ac28c70355309533f19c"
    hash2       = "cb576c42df90a554f241d4a5ba0dee1dfcb9caf661cf46a2800b743aa592e644"
    hash3       = "9db5f5694048d441a47fe4382700213cc288d4fba152eec7b99fdd310a50ef7d"

  strings:
    $s1 = "eturn \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s2 = "tion fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return" ascii
    $s3 = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"" ascii
    $s4 = "eturn \"SUi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s5 = "fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Sx" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}