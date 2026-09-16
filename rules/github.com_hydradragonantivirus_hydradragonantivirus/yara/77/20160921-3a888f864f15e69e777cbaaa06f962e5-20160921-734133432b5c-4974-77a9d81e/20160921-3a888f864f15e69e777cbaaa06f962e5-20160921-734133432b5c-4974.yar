rule _20160921_3a888f864f15e69e777cbaaa06f962e5_20160921_734133432b5c_4974 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a888f864f15e69e777cbaaa06f962e5.js, 20160921_734133432b5c6f9bde8604a5856b0226.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "65826487c59973db0339cbaf1f8e99201516dc26d5bdf1991855fafe9cbc5da1"
    hash2       = "ae166a3e50bde57db63d39eeb168b02f14d45f281093c1420136eb1293fd87ef"

  strings:
    $s1 = "){return \"IPu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ve\";})" ascii
    $s2 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return" ascii
    $s3 = "urn \"Hs\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"SUi\";})(),(f" ascii
    $s4 = "on fuck(){return \"Av\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"I" ascii
    $s5 = "ck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}