rule _20160921_5f7be0b4d162caa40e1fc5a06f9f867a_20160921_aab5fb25ea89_3841 {
  meta:
    description = "datamaliciousorder - from files 20160921_5f7be0b4d162caa40e1fc5a06f9f867a.js, 20160921_aab5fb25ea8971982ac223655d50aba2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9a6e02fec1a6c5d0a6813da97edfb28eb017c5563b8e8c2205eb08ae1c6ec4e3"
    hash2       = "0387ef653c0ac9c5d0aaf638bde80688e7b6b279a435dcab3ff679313abfab3c"

  strings:
    $s1 = "ion fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return" ascii
    $s2 = " fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"A" ascii
    $s3 = "function fuck(){return \"We\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){ret" ascii
    $s4 = "e\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s5 = "){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";}" ascii
    $s6 = "uck(){return \"Jh\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Qh" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}