rule _20160921_214342143d6b7e971a1c8d2679379cb7_20160921_2195f5432b2f_3511 {
  meta:
    description = "datamaliciousorder - from files 20160921_214342143d6b7e971a1c8d2679379cb7.js, 20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa.js, 20160921_c42fb5c75aea2648513013ad2eed9aaf.js, 20160921_dc1ff053e9dd688459c33dc98e88d636.js, 20160921_e6b8063519cd61bbba9375bf86215501.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8dcc208c118a95c2f88df14e844ed832ee1e06bdf992329e8a721bd7aaa936e8"
    hash2       = "8753bd153b88da9a4351b5d6a0111d7af66a0f18e8b8a42beee11ad2916dc183"
    hash3       = "5c8cdf3dbb94e197c36e5744084d12e198ecdab7243d67654934aa1cc9bf7ae9"
    hash4       = "18a890096a5714e518b28d3f50f6487cfbc4164418daae1842b7d724e2c26bd6"
    hash5       = "70ad2f9c8f844d4c80b1d4ce0f71f62f74e64671ae11d2d3af8e6ec764993403"

  strings:
    $s1 = "),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Wo0\";})(),(function fuck()" ascii
    $s2 = "tion fuck(){return \"ZWu\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retur" ascii
    $s3 = "\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function f" ascii
    $s4 = "unction fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){re" ascii
    $s5 = "s\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Wo0\";})(),(function " ascii
    $s6 = "on fuck(){return \"DWe\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}