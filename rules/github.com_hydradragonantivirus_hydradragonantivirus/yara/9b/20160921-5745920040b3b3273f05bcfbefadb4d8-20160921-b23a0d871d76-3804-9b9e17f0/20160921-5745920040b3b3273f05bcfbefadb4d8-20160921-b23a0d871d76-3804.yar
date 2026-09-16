rule _20160921_5745920040b3b3273f05bcfbefadb4d8_20160921_b23a0d871d76_3804 {
  meta:
    description = "datamaliciousorder - from files 20160921_5745920040b3b3273f05bcfbefadb4d8.js, 20160921_b23a0d871d76c64a3c71f0b0f52faaa8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "86b6dab46ebbd6ed243e73b97070b8a7b74178533a419d7a22c3842a74574534"
    hash2       = "02969139df11550b994530c0bcbc6d946b6e49105015e9475f5de3942d78e5a1"

  strings:
    $s1 = "k(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\"" ascii
    $s2 = " \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(func" ascii
    $s3 = "uck(){return \"RAi\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo" ascii
    $s4 = " \"Xw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Xw\";})(),(funct" ascii
    $s5 = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Na" ascii
    $s6 = "){return \"MBg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Np\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}