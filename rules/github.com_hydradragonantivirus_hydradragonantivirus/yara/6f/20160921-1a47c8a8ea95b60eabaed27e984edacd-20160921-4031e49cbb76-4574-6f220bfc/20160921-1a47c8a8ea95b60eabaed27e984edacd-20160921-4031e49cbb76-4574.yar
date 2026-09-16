rule _20160921_1a47c8a8ea95b60eabaed27e984edacd_20160921_4031e49cbb76_4574 {
  meta:
    description = "datamaliciousorder - from files 20160921_1a47c8a8ea95b60eabaed27e984edacd.js, 20160921_4031e49cbb76e44dd58fa572b63a00c7.js, 20160921_62f4f68c59540f36d255485f0f0e37c9.js, 20160921_e2617d9e437c12b61ada4700f8e426b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b5a5f062c9d94508668ecb987b9d855fefbcdb1cf10f3efded37c21fc6893b0c"
    hash2       = "42519dff3fd2ed2dc9bcd0f12a16fe310be93f90efd5d40110f336dc5010d050"
    hash3       = "4e9c7d3504791445d99c11b26a2aad12b3de66c6ef81ae8c7032e0310dda3d06"
    hash4       = "732b58fdcabccece6ef3ce710e7c0ba505cd66ea292afad6fac2c48739151b46"

  strings:
    $s1 = "turn \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})()" ascii
    $s2 = "){return \"USf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";}" ascii
    $s3 = "g\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(function " ascii
    $s4 = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IR" ascii
    $s5 = "turn \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}