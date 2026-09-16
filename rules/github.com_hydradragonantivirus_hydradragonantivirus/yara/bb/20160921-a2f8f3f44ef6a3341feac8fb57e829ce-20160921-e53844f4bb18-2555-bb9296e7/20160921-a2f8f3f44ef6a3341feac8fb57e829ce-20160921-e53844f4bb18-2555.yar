rule _20160921_a2f8f3f44ef6a3341feac8fb57e829ce_20160921_e53844f4bb18_2555 {
  meta:
    description = "datamaliciousorder - from files 20160921_a2f8f3f44ef6a3341feac8fb57e829ce.js, 20160921_e53844f4bb18305322896332fbd017e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "619e82812300e58dd7cd06b8fbcf2f7e3f6757812cc075603c82363ab6481758"
    hash2       = "b8484bab412a47fffb0a694f32ca5de3480841bd1c0806d0a7e6e86dfd21de6c"

  strings:
    $s1 = "\"IPu\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xg\";})(),(functi" ascii
    $s2 = "ck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs" ascii
    $s3 = "k(){return \"IPu\";})(),(function fuck(){return \"AJs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu" ascii
    $s4 = "on fuck(){return \"SUi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return " ascii
    $s5 = "\"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(funct" ascii
    $s6 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retur" ascii
    $s7 = "function fuck(){return \"MIl\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){r" ascii
    $s8 = "n \"Bz\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"GNm\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}