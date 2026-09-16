rule _20160921_50b14bf13c50bc31f09e3c583e1d422d_20160921_63a82ecb2e4e_1862 {
  meta:
    description = "datamaliciousorder - from files 20160921_50b14bf13c50bc31f09e3c583e1d422d.js, 20160921_63a82ecb2e4eb3b0dd878bbec885c469.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9aab1a9f889ee14c72c5b3718595b8a66b04e749b1cb75ceb264874c173aeab"
    hash2       = "0e9de62be8773f33e42da56c84c9c85d07f7c2616909543479f7803e6794a9ef"

  strings:
    $s1  = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s2  = "on fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return " ascii
    $s3  = "eturn \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(" ascii
    $s4  = "n fuck(){return \"Mw\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"XF" ascii
    $s5  = "return \"We\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s6  = "return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s7  = "ck(){return \"MBg\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"MUs\"" ascii
    $s8  = "return \"Nm\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"UOe\";})()" ascii
    $s9  = " fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"" ascii
    $s10 = ")(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"SUi\";})(),(function fuck" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}