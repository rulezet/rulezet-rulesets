rule _20160921_d4e094c14df45f61de0e1163f51e03e6_20160921_e0f7b2a32a09_3152 {
  meta:
    description = "datamaliciousorder - from files 20160921_d4e094c14df45f61de0e1163f51e03e6.js, 20160921_e0f7b2a32a0967097baa59c67369ba3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2877b2ace685858babd88dd0ef1659f49f21c3f8b907e5b3889ec46bf3a7104a"
    hash2       = "d527617da74d553b6d56b37f7b101c14280b85e5e40e1f565fe396f8b97b29a2"

  strings:
    $s1 = "rn \"ZVi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"XCr\";})(),(fu" ascii
    $s2 = "uck(){return \"Av\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"FJs" ascii
    $s3 = "return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UXf\";})" ascii
    $s4 = "(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){" ascii
    $s5 = "return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"XFd\";})" ascii
    $s6 = "ck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MUs" ascii
    $s7 = "\"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}