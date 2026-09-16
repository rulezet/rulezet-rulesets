rule _20160921_64060d97e498db57bf68dbb08be86bba_20160921_7e15ac275536_5317 {
  meta:
    description = "datamaliciousorder - from files 20160921_64060d97e498db57bf68dbb08be86bba.js, 20160921_7e15ac2755366d4644a83de8ec9c1a47.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "30a02b9f75ed0112affe2c698cfdbe2ec2a5bc4d8248ac34ebe13e072bd212f0"
    hash2       = "97eaf7c50f22bfc94f97a02e5e83a8f1fb3583717fb9f4a6666ae882ea4d6f55"

  strings:
    $s1 = "nction fuck(){return \"Zy\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retu" ascii
    $s2 = " \"DHd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(fun" ascii
    $s3 = "urn \"MBg\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s4 = "ion fuck(){return \"Jh\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s5 = "ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Wo0\";})(),(functi" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}