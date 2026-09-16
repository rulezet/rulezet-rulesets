rule _20160921_41f7b3abc606ff1ddad7593361eaa449_20160921_7c5b5eaba938_5038 {
  meta:
    description = "datamaliciousorder - from files 20160921_41f7b3abc606ff1ddad7593361eaa449.js, 20160921_7c5b5eaba938fa91eb6a9414212e13f9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "53e06a7234c6522ba26a61e46d13312e1063594b0e33bec9fae49d2dc4b77c28"
    hash2       = "9b25331c24a00cfccf7bf1604f7df1d245543734bf5553f0a7c3c911bb74cbb8"

  strings:
    $s1 = "eturn \"IPu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Jh\";})()," ascii
    $s2 = " \"Zy\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"SUi\";})(),(func" ascii
    $s3 = "uck(){return \"GWo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz" ascii
    $s4 = "unction fuck(){return \"OQr\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){ret" ascii
    $s5 = "ction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}