rule _20160921_50b14bf13c50bc31f09e3c583e1d422d_20160921_afb633ee817d_1861 {
  meta:
    description = "datamaliciousorder - from files 20160921_50b14bf13c50bc31f09e3c583e1d422d.js, 20160921_afb633ee817d9b15b91ed82a059939fc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b9aab1a9f889ee14c72c5b3718595b8a66b04e749b1cb75ceb264874c173aeab"
    hash2       = "7a4e330bd3ec71aa3dc8fd3d5b2fa656b04d49cb5ee4e5478a50a6336c5bf9e5"

  strings:
    $s1  = " \"DAa\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(func" ascii
    $s2  = "uck(){return \"Cd\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"RAi" ascii
    $s3  = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return " ascii
    $s4  = "return \"XHj\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})" ascii
    $s5  = "urn \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"UOe\";})(),(f" ascii
    $s6  = ",(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"QTc\";})(),(function fuck(){r" ascii
    $s7  = "uck(){return \"KVh\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Xw" ascii
    $s8  = "return \"Xw\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"MUs\";})()," ascii
    $s9  = "ck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Za\"" ascii
    $s10 = "k(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Wo0" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}