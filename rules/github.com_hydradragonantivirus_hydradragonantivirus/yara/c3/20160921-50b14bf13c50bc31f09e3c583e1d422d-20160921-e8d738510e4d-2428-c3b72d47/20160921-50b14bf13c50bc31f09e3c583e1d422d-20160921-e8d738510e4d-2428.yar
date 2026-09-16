rule _20160921_50b14bf13c50bc31f09e3c583e1d422d_20160921_e8d738510e4d_2428 {
  meta:
    description = "datamaliciousorder - from files 20160921_50b14bf13c50bc31f09e3c583e1d422d.js, 20160921_e8d738510e4d2e0efb6c7aa18a7a58d8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9aab1a9f889ee14c72c5b3718595b8a66b04e749b1cb75ceb264874c173aeab"
    hash2       = "e1cd4a36522d2ad8fc8435b6cb64d8e572d8b31d4203885fa375f539a3ea7891"

  strings:
    $s1 = "eturn \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Za\";})(),(" ascii
    $s2 = "){return \"Yk\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";}" ascii
    $s3 = " fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"B" ascii
    $s4 = "rn \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Fv\";})(),(fun" ascii
    $s5 = "n fuck(){return \"XFd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s6 = "turn \"CCb\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";})()," ascii
    $s7 = "urn \"CCb\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Jo\";})(),(f" ascii
    $s8 = "(function fuck(){return \"Qh\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Za\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}