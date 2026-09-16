rule _20160921_42353ce257534ed06a8c73cebdde12dc_20160921_64060d97e498_5043 {
  meta:
    description = "datamaliciousorder - from files 20160921_42353ce257534ed06a8c73cebdde12dc.js, 20160921_64060d97e498db57bf68dbb08be86bba.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "68261e17878fc3b618b0fec34ae97fb6fea1090c52fff206192cb972d23b2b35"
    hash2       = "30a02b9f75ed0112affe2c698cfdbe2ec2a5bc4d8248ac34ebe13e072bd212f0"

  strings:
    $s1 = "ck(){return \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\"" ascii
    $s2 = "on fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s3 = "eturn \"LGo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"USf\";})()" ascii
    $s4 = "{return \"USf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(" ascii
    $s5 = "n fuck(){return \"RAi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}