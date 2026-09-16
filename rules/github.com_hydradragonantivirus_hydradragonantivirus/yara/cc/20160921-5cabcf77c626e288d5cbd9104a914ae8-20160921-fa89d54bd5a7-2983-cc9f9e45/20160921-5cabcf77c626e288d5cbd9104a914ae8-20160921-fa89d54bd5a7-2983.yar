rule _20160921_5cabcf77c626e288d5cbd9104a914ae8_20160921_fa89d54bd5a7_2983 {
  meta:
    description = "datamaliciousorder - from files 20160921_5cabcf77c626e288d5cbd9104a914ae8.js, 20160921_fa89d54bd5a7a27defe09d5a56b5a881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9493e4251106014081e4b141c6296c51b00c9ba7a799bcb978ea6226cd127d34"
    hash2       = "30f2a7c2562ef79254c8129be50246b9c41eb24f000c8cfbd0f4f8c28b49b00f"

  strings:
    $s1 = "ction fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){retur" ascii
    $s2 = "k(){return \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\"" ascii
    $s3 = "){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";}" ascii
    $s4 = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})()" ascii
    $s5 = "rn \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\";})(),(fu" ascii
    $s6 = "fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IR" ascii
    $s7 = "on fuck(){return \"UOe\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}