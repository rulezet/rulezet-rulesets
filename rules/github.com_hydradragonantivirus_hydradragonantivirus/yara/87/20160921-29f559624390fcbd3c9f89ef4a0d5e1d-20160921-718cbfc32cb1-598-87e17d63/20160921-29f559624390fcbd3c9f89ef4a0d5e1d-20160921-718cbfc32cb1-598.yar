rule _20160921_29f559624390fcbd3c9f89ef4a0d5e1d_20160921_718cbfc32cb1_598 {
  meta:
    description = "datamaliciousorder - from files 20160921_29f559624390fcbd3c9f89ef4a0d5e1d.js, 20160921_718cbfc32cb1f435745a5a005d3f190b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c15ee6fcf772accd2bb85369b8381c6c2cefb7139e589532becec07720a57867"
    hash2       = "7611b8615a5a07f89bc6a867e9232ae443f0ff2bb48d960d2254e1390a27fdee"

  strings:
    $s1  = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){" ascii
    $s2  = "ction fuck(){return \"Jo\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){retur" ascii
    $s3  = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"CCb\";})(),(function fuck(" ascii
    $s4  = "rn \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Jg\";})(),(fun" ascii
    $s5  = "urn \"GWo\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s6  = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s7  = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return" ascii
    $s8  = "ck(){return \"EHo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"CCb" ascii
    $s9  = "\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"TTs\";})(),(function " ascii
    $s10 = "eturn \"Za\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()," ascii
    $s11 = "nction fuck(){return \"Np\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retur" ascii
    $s12 = "uck(){return \"IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"MBg" ascii
    $s13 = "ction fuck(){return \"MUs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s14 = "uck(){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Ik" ascii
    $s15 = "(function fuck(){return \"MBg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){r" ascii
    $s16 = ",(function fuck(){return \"XHj\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){" ascii
    $s17 = "(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"QTc\";}" ascii
    $s18 = ")(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IPu\";})(),(function fuck" ascii
    $s19 = "eturn \"DWe\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s20 = "ction fuck(){return \"UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}