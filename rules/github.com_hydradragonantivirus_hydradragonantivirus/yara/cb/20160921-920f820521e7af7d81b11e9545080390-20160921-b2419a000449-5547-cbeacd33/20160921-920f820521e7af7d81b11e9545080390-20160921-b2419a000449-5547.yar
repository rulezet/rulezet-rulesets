rule _20160921_920f820521e7af7d81b11e9545080390_20160921_b2419a000449_5547 {
  meta:
    description = "datamaliciousorder - from files 20160921_920f820521e7af7d81b11e9545080390.js, 20160921_b2419a000449b12cbd6aff3732baf55d.js, 20160921_bd6b4f506f527835a48516850a16c1a6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c4a6a94fe43f214f35574405d899a6d61259c2b1135c1ecf399630de11c6dea3"
    hash2       = "ea7b5520c177b4adf74565706c3c8ed38eed94f30b6927b0ceb647f7f768a2b5"
    hash3       = "ccc844c2bc8943a231b37e8fbf1d55bab57686844fc9486bd597d3b00ae72c70"

  strings:
    $s1 = "fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"N" ascii
    $s2 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retu" ascii
    $s3 = "){return \"UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"ADy\";" ascii
    $s4 = "a\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(function" ascii
    $s5 = "ction fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}