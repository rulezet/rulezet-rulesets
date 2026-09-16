rule _20160921_3282034bab74b3776acf585e8adfca92_20160921_b2419a000449_925 {
  meta:
    description = "datamaliciousorder - from files 20160921_3282034bab74b3776acf585e8adfca92.js, 20160921_b2419a000449b12cbd6aff3732baf55d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0b99efa289490e150d7af72ae3e0fb067880b4a22c16ba75dec34f9945b5c2df"
    hash2       = "ea7b5520c177b4adf74565706c3c8ed38eed94f30b6927b0ceb647f7f768a2b5"

  strings:
    $s1  = "function fuck(){return \"DAa\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){r" ascii
    $s2  = " \"Sx\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ot\";})(),(func" ascii
    $s3  = "uck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"Nm" ascii
    $s4  = "Qh\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(functio" ascii
    $s5  = "k(){return \"Ve\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";" ascii
    $s6  = "nction fuck(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){ret" ascii
    $s7  = "(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s8  = "n fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return " ascii
    $s9  = "Bg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Xg\";})(),(function " ascii
    $s10 = "urn \"ZWu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s11 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IR" ascii
    $s12 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){retur" ascii
    $s13 = "urn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"We\";})(),(f" ascii
    $s14 = "k\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function" ascii
    $s15 = "nction fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){ret" ascii
    $s16 = "{return \"IOs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";}" ascii
    $s17 = "){return \"Wo0\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";" ascii
    $s18 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"S" ascii
    $s19 = "rn \"Vf\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s20 = "ction fuck(){return \"Yk\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}