rule _20160921_aab5fb25ea8971982ac223655d50aba2_20160921_bd40742bedf8_5620 {
  meta:
    description = "datamaliciousorder - from files 20160921_aab5fb25ea8971982ac223655d50aba2.js, 20160921_bd40742bedf80aa0091b1fafd0a7ba4b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0387ef653c0ac9c5d0aaf638bde80688e7b6b279a435dcab3ff679313abfab3c"
    hash2       = "85233a675e78f03dbcaaf2a32253b0d4a36e5c5e7008041477e560a514d38729"

  strings:
    $s1 = ")(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Mw\";})(),(function fuck(" ascii
    $s2 = "(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Nm\";})(),(function fuck(" ascii
    $s3 = "\"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"NKq\";})(),(functi" ascii
    $s4 = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return " ascii
    $s5 = "k(){return \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Hs\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}