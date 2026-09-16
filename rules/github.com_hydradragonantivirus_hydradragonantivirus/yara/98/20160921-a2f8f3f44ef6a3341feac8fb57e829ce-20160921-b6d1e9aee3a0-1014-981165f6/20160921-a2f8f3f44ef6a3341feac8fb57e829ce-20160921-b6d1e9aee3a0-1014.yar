rule _20160921_a2f8f3f44ef6a3341feac8fb57e829ce_20160921_b6d1e9aee3a0_1014 {
  meta:
    description = "datamaliciousorder - from files 20160921_a2f8f3f44ef6a3341feac8fb57e829ce.js, 20160921_b6d1e9aee3a026c6f266b107f0b88f18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "619e82812300e58dd7cd06b8fbcf2f7e3f6757812cc075603c82363ab6481758"
    hash2       = "e95dafe7c61e6b4aa30cf1d0f5e7ac22599967edab3c0a7152e74671d99054e2"

  strings:
    $s1  = "urn \"Jo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GNm\";})(),(" ascii
    $s2  = " fuck(){return \"Qh\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"N" ascii
    $s3  = "uck(){return \"Py\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"CCb" ascii
    $s4  = "AUx\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ZWu\";})(),(functi" ascii
    $s5  = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"DWe\"" ascii
    $s6  = "rn \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Cd\";})(),(fu" ascii
    $s7  = "){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\";})" ascii
    $s8  = "return \"Za\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"UOe\";})(" ascii
    $s9  = " fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ZW" ascii
    $s10 = "})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuc" ascii
    $s11 = "\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Py\";})(),(function " ascii
    $s12 = "unction fuck(){return \"Fv\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){ret" ascii
    $s13 = "ion fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s14 = "turn \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(" ascii
    $s15 = "\"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(fun" ascii
    $s16 = "turn \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Py\";})(),(" ascii
    $s17 = "turn \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"OPz\";})()," ascii
    $s18 = "n \"Py\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s19 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}