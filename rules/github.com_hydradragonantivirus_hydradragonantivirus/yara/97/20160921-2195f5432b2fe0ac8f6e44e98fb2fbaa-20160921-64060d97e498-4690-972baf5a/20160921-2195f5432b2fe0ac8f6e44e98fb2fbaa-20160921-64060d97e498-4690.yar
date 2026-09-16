rule _20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa_20160921_64060d97e498_4690 {
  meta:
    description = "datamaliciousorder - from files 20160921_2195f5432b2fe0ac8f6e44e98fb2fbaa.js, 20160921_64060d97e498db57bf68dbb08be86bba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8753bd153b88da9a4351b5d6a0111d7af66a0f18e8b8a42beee11ad2916dc183"
    hash2       = "30a02b9f75ed0112affe2c698cfdbe2ec2a5bc4d8248ac34ebe13e072bd212f0"

  strings:
    $s1 = "turn \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})()," ascii
    $s2 = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Wo0\";})()," ascii
    $s3 = "k(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"MBg\";" ascii
    $s4 = "ck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\"" ascii
    $s5 = "nction fuck(){return \"Vf\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}