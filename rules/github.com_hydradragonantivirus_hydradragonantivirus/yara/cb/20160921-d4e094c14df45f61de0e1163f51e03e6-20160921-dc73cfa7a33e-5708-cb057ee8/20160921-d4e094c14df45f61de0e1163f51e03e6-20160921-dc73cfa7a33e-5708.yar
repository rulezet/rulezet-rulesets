rule _20160921_d4e094c14df45f61de0e1163f51e03e6_20160921_dc73cfa7a33e_5708 {
  meta:
    description = "datamaliciousorder - from files 20160921_d4e094c14df45f61de0e1163f51e03e6.js, 20160921_dc73cfa7a33eb762f38614c69a95919d.js, 20160921_e53844f4bb18305322896332fbd017e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2877b2ace685858babd88dd0ef1659f49f21c3f8b907e5b3889ec46bf3a7104a"
    hash2       = "50e80269adbbca38f500219eaf7cec16f396b3d8a7c56d342b2e4839819ea598"
    hash3       = "b8484bab412a47fffb0a694f32ca5de3480841bd1c0806d0a7e6e86dfd21de6c"

  strings:
    $s1 = " \"Mw\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"LGo\";})(),(func" ascii
    $s2 = " fuck(){return \"Ff\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Z" ascii
    $s3 = "ck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"CTm" ascii
    $s4 = "urn \"Za\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s5 = "k(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}