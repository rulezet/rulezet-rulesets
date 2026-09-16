rule _20160921_15779a074d56c3a097b4f7014a2c30f9_20160921_42353ce25753_4485 {
  meta:
    description = "datamaliciousorder - from files 20160921_15779a074d56c3a097b4f7014a2c30f9.js, 20160921_42353ce257534ed06a8c73cebdde12dc.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "aac4640bf20c6d05cb7c57f9703d60beee7ea9dfc98b851cabc5976b3d117b8d"
    hash2       = "68261e17878fc3b618b0fec34ae97fb6fea1090c52fff206192cb972d23b2b35"

  strings:
    $s1 = "return \"Vb\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})()" ascii
    $s2 = "\"UOe\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(func" ascii
    $s3 = "turn \"Ai\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s4 = "rn \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Np\";})(),(fun" ascii
    $s5 = "unction fuck(){return \"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}