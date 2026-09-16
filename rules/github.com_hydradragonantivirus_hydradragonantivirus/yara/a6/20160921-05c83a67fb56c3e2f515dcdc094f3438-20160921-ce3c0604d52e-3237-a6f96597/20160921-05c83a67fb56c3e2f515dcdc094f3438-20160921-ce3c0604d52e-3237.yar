rule _20160921_05c83a67fb56c3e2f515dcdc094f3438_20160921_ce3c0604d52e_3237 {
  meta:
    description = "datamaliciousorder - from files 20160921_05c83a67fb56c3e2f515dcdc094f3438.js, 20160921_ce3c0604d52e9dc9119cefedfee34385.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0535a055f646391a67e495ab3466f375b47d00382cf1ac28c70355309533f19c"
    hash2       = "27a20a400d7aa13737d230acf36a2170494c7da92e72552775d19562ba331fdc"

  strings:
    $s1 = "ction fuck(){return \"Cd\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return" ascii
    $s2 = "turn \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"To\";})(),(" ascii
    $s3 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"UXf\";})(),(function fuck" ascii
    $s4 = " \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Py\";})(),(fun" ascii
    $s5 = "),(function fuck(){return \"Nm\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){" ascii
    $s6 = "){return \"Py\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";}" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}