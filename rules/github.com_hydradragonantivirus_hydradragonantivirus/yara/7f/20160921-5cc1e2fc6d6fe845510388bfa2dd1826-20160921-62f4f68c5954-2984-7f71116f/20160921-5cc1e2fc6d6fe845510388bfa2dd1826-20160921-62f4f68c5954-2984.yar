rule _20160921_5cc1e2fc6d6fe845510388bfa2dd1826_20160921_62f4f68c5954_2984 {
  meta:
    description = "datamaliciousorder - from files 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js, 20160921_62f4f68c59540f36d255485f0f0e37c9.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"
    hash2       = "4e9c7d3504791445d99c11b26a2aad12b3de66c6ef81ae8c7032e0310dda3d06"

  strings:
    $s1 = "u\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function f" ascii
    $s2 = "urn \"XHj\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s3 = "turn \"LGo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Xw\";})(),(" ascii
    $s4 = "{return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"QTc\";})" ascii
    $s5 = "turn \"Ai\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s6 = "),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"SUi\";})(),(function fuck()" ascii
    $s7 = " \"Ai\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}