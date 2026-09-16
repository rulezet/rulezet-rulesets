rule _20160921_5e30fe0c691277f3c6d0814d796ba918_20160921_7c5b5eaba938_5259 {
  meta:
    description = "datamaliciousorder - from files 20160921_5e30fe0c691277f3c6d0814d796ba918.js, 20160921_7c5b5eaba938fa91eb6a9414212e13f9.js, 20160921_e0f7b2a32a0967097baa59c67369ba3a.js, 20160921_f5230fc58405f25233bda6815654bd6e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7cac2594d8c0286d3110fd3705816d41052df49790da39881cedd79b8cb5c6ed"
    hash2       = "9b25331c24a00cfccf7bf1604f7df1d245543734bf5553f0a7c3c911bb74cbb8"
    hash3       = "d527617da74d553b6d56b37f7b101c14280b85e5e40e1f565fe396f8b97b29a2"
    hash4       = "1a813dda7d0088c45bb00563ea79982995ec1337c805380117fe705f80c51c64"

  strings:
    $s1 = "unction fuck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){ret" ascii
    $s2 = "k(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\"" ascii
    $s3 = "urn \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})()," ascii
    $s4 = "fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IP" ascii
    $s5 = "{return \"USf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}