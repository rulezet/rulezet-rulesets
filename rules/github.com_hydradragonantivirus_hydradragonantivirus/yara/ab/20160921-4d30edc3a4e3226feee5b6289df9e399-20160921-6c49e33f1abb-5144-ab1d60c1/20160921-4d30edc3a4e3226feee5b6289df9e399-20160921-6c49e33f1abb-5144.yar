rule _20160921_4d30edc3a4e3226feee5b6289df9e399_20160921_6c49e33f1abb_5144 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d30edc3a4e3226feee5b6289df9e399.js, 20160921_6c49e33f1abb3ca2b0ff12a4878e38c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"
    hash2       = "b2c5f6e5a1ebce2cb0eb54f0d28ea21ab88b07dc646376bb3fc5ce29af1615aa"

  strings:
    $s1 = "ion fuck(){return \"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return " ascii
    $s2 = "unction fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){ret" ascii
    $s3 = "ck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf" ascii
    $s4 = "LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(functi" ascii
    $s5 = "unction fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}