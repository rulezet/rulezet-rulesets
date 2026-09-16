rule _20160921_85f2776f4fe640d2373f51ddbc697659_20160921_b23a0d871d76_5470 {
  meta:
    description = "datamaliciousorder - from files 20160921_85f2776f4fe640d2373f51ddbc697659.js, 20160921_b23a0d871d76c64a3c71f0b0f52faaa8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0604503e68d6aa73ca3bbdb29b958ea47ad4c81b2f77ad9db2b0e8467b1c870d"
    hash2       = "02969139df11550b994530c0bcbc6d946b6e49105015e9475f5de3942d78e5a1"

  strings:
    $s1 = "(),(function fuck(){return \"USf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck" ascii
    $s2 = "\"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(funct" ascii
    $s3 = "k(){return \"Yk\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";}" ascii
    $s4 = " \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Np\";})(),(funct" ascii
    $s5 = "eturn \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})()," ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}