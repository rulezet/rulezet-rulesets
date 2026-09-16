rule _20160921_6c49e33f1abb3ca2b0ff12a4878e38c8_20160921_c07f026b9458_5358 {
  meta:
    description = "datamaliciousorder - from files 20160921_6c49e33f1abb3ca2b0ff12a4878e38c8.js, 20160921_c07f026b9458324f489ec08b7859e758.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b2c5f6e5a1ebce2cb0eb54f0d28ea21ab88b07dc646376bb3fc5ce29af1615aa"
    hash2       = "ea2be3685bc68d327f9689a9fc4de597314db751f1eacc3ff5fbee0dd0397db0"

  strings:
    $s1 = "ck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv" ascii
    $s2 = "(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";}" ascii
    $s3 = "n \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Np\";})(),(fun" ascii
    $s4 = "UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(functi" ascii
    $s5 = "MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}