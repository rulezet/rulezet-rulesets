rule _20160921_06a7c56eaf19048ede06f33b655f2bc5_20160921_469953d98331_1325 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a7c56eaf19048ede06f33b655f2bc5.js, 20160921_469953d9833167e141d9f086f1f41437.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3971833c2ab49de293c47181e999db88e5cad0eaddc5aa38a2516eeac1cab29d"
    hash2       = "e29808d818b8f5ea60d0baa8d6c3284d3673878f7f4309c5981ced86dc40c5f1"

  strings:
    $s1  = "ion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return " ascii
    $s2  = ")(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Xw\";})(),(function fuck()" ascii
    $s3  = "Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"IOs\";})(),(functio" ascii
    $s4  = "on fuck(){return \"EHo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s5  = "ction fuck(){return \"SUi\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){retur" ascii
    $s6  = "u\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s7  = "),(function fuck(){return \"XFd\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"IOs\";})(),(function fuck(" ascii
    $s8  = " fuck(){return \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"YA" ascii
    $s9  = " \"Xw\";})(),(function fuck(){return \"LLv\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"Xw\";})(),(func" ascii
    $s10 = "eturn \"YQt\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(" ascii
    $s11 = " fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Xg" ascii
    $s12 = "{return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})" ascii
    $s13 = "turn \"Xw\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Fv\";})(),(fu" ascii
    $s14 = "eturn \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"FJs\";})()" ascii
    $s15 = "rn \"GJx\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}