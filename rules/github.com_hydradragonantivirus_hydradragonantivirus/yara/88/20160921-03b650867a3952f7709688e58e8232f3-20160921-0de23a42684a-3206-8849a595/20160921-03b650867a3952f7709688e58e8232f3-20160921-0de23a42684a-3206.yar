rule _20160921_03b650867a3952f7709688e58e8232f3_20160921_0de23a42684a_3206 {
  meta:
    description = "datamaliciousorder - from files 20160921_03b650867a3952f7709688e58e8232f3.js, 20160921_0de23a42684ac14027d562ff3e5fb6a8.js, 20160921_aab5fb25ea8971982ac223655d50aba2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a775853212fe6663d7c077a64c0d4c851d4b7f261a6c0846b4552b556e12a5fe"
    hash2       = "7237be0906b854ec3890943cde0c9a731117b836078be4256fe37413dd372a66"
    hash3       = "0387ef653c0ac9c5d0aaf638bde80688e7b6b279a435dcab3ff679313abfab3c"

  strings:
    $s1 = "ction fuck(){return \"Mw\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return " ascii
    $s2 = "return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Dc\";})(),(" ascii
    $s3 = "Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"Ve\";})(),(function " ascii
    $s4 = "k(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\"" ascii
    $s5 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){ret" ascii
    $s6 = " fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"V" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}