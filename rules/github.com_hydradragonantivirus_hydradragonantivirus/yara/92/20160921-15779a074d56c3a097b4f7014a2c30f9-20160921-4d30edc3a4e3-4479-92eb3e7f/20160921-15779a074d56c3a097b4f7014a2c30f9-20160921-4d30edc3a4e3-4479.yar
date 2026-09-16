rule _20160921_15779a074d56c3a097b4f7014a2c30f9_20160921_4d30edc3a4e3_4479 {
  meta:
    description = "datamaliciousorder - from files 20160921_15779a074d56c3a097b4f7014a2c30f9.js, 20160921_4d30edc3a4e3226feee5b6289df9e399.js, 20160921_c07f026b9458324f489ec08b7859e758.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aac4640bf20c6d05cb7c57f9703d60beee7ea9dfc98b851cabc5976b3d117b8d"
    hash2       = "d28b5e72375443a9ef1a43fee185a0e5563672a0764eef4f58a90a27302162ea"
    hash3       = "ea2be3685bc68d327f9689a9fc4de597314db751f1eacc3ff5fbee0dd0397db0"

  strings:
    $s1 = "eturn \"LGo\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s2 = "urn \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"FJs\";})(),(" ascii
    $s3 = "Go\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Xw\";})(),(function" ascii
    $s4 = "){return \"Ug\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"MBg\";})" ascii
    $s5 = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"USf\";})(),(function fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}