rule _20160921_18f3609106b0af59da0b1200fe14abc1_20160921_bd6b4f506f52_4557 {
  meta:
    description = "datamaliciousorder - from files 20160921_18f3609106b0af59da0b1200fe14abc1.js, 20160921_bd6b4f506f527835a48516850a16c1a6.js, 20160921_e4c63c3b699efd2f5fe2739b016a938a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "95fb9e6292746461417b0e539747d500c780ad17cb775a9db031f77eaa53a3e2"
    hash2       = "ccc844c2bc8943a231b37e8fbf1d55bab57686844fc9486bd597d3b00ae72c70"
    hash3       = "9d5d6c2986818649619806d890aad49cda8d0da47fe67f38388e5441a53382a0"

  strings:
    $s1 = "{return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";}" ascii
    $s2 = "),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){" ascii
    $s3 = "uck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LG" ascii
    $s4 = "fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"N" ascii
    $s5 = "tion fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}