rule _20160921_64060d97e498db57bf68dbb08be86bba_20160921_78345276f684_5314 {
  meta:
    description = "datamaliciousorder - from files 20160921_64060d97e498db57bf68dbb08be86bba.js, 20160921_78345276f684d53628bbcac810994182.js, 20160921_d97203a3a0e9b5b38b8653b55adf994e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30a02b9f75ed0112affe2c698cfdbe2ec2a5bc4d8248ac34ebe13e072bd212f0"
    hash2       = "17b203684b4f2284de883c81e8fef63ea03c36bd0599ccb85d3175be35d9ac6d"
    hash3       = "4500fdca6df5cc18d7f5e360c950817a72f82196c8ae55d8bcdf74d96a8bba21"

  strings:
    $s1 = "function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){re" ascii
    $s2 = "urn \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(f" ascii
    $s3 = "eturn \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ml\";})()," ascii
    $s4 = " \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Jo\";})(),(fun" ascii
    $s5 = "(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"RAi\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}