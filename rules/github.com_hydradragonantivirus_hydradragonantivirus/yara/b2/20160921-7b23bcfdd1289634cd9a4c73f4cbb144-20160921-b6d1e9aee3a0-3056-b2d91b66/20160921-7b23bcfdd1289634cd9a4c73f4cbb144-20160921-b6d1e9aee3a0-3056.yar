rule _20160921_7b23bcfdd1289634cd9a4c73f4cbb144_20160921_b6d1e9aee3a0_3056 {
  meta:
    description = "datamaliciousorder - from files 20160921_7b23bcfdd1289634cd9a4c73f4cbb144.js, 20160921_b6d1e9aee3a026c6f266b107f0b88f18.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7a94fbc46ac51a544406f9a59bf405cd1e19e8e6681d7feacbc81e5ab7d4a50b"
    hash2       = "e95dafe7c61e6b4aa30cf1d0f5e7ac22599967edab3c0a7152e74671d99054e2"

  strings:
    $s1 = "nction fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){retu" ascii
    $s2 = "nction fuck(){return \"Yk\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){retur" ascii
    $s3 = "(),(function fuck(){return \"DAa\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IRn\";})(),(function fuck" ascii
    $s4 = " \"CTm\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MUs\";})(),(fun" ascii
    $s5 = "return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Jh\";})()," ascii
    $s6 = "\"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"LGo\";})(),(func" ascii
    $s7 = "ck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MIl" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}