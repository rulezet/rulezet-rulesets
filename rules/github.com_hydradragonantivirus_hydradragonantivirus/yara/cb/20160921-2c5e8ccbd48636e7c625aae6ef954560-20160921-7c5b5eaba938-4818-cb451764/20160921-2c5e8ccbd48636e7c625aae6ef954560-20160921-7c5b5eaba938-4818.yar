rule _20160921_2c5e8ccbd48636e7c625aae6ef954560_20160921_7c5b5eaba938_4818 {
  meta:
    description = "datamaliciousorder - from files 20160921_2c5e8ccbd48636e7c625aae6ef954560.js, 20160921_7c5b5eaba938fa91eb6a9414212e13f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70244ca5fa124af09b1f94729567c09dbc52c05035ee7d20cbe87d35e1fe63c8"
    hash2       = "9b25331c24a00cfccf7bf1604f7df1d245543734bf5553f0a7c3c911bb74cbb8"

  strings:
    $s1 = "uck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq" ascii
    $s2 = "nction fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retu" ascii
    $s3 = "turn \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})()," ascii
    $s4 = "nction fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retu" ascii
    $s5 = "tion fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}