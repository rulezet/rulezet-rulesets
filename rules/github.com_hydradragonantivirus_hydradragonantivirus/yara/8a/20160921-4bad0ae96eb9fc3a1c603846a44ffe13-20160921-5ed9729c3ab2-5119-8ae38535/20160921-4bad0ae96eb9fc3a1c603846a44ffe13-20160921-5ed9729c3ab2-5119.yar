rule _20160921_4bad0ae96eb9fc3a1c603846a44ffe13_20160921_5ed9729c3ab2_5119 {
  meta:
    description = "datamaliciousorder - from files 20160921_4bad0ae96eb9fc3a1c603846a44ffe13.js, 20160921_5ed9729c3ab2cb9d37d8a088af1aba59.js, 20160921_fa8c93ef210d8b4c6831cb1425f1dc9b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a99f235f58613323f5c58def3503d47959f4a77f0697e30c75b6d221c4b40806"
    hash2       = "c5908838424a9cae8eb5587cff7048056b427db1deb512dcbe9ca852a402e03d"
    hash3       = "7e7bb1d2ade80c23d5462f8e4a470a3c3245b07b8a709a3c911ff76a8c32da35"

  strings:
    $s1 = "){return \"Jh\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Zy\";})" ascii
    $s2 = "fuck(){return \"Ai\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ug" ascii
    $s3 = "UXf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ug\";})(),(functio" ascii
    $s4 = "on fuck(){return \"ZLd\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s5 = "urn \"DRx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"Jh\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}