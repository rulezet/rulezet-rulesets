rule _20160921_3823f4aff4d341a62056d936e59de44c_20160921_b714100d69b9_4935 {
  meta:
    description = "datamaliciousorder - from files 20160921_3823f4aff4d341a62056d936e59de44c.js, 20160921_b714100d69b955de920a302ff8bef7db.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d0b475c02138425371c1df69faa8ac5c3d739764950c4a65034372b4455ac04d"
    hash2       = "fc43d54db3c24d6f7ce2d47a45ffcd0768d5cfe90e405322e477be98fe4a8170"

  strings:
    $s1 = "nction fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){retur" ascii
    $s2 = "on fuck(){return \"OQr\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return " ascii
    $s3 = "fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return \"Cs" ascii
    $s4 = "MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Py\";})(),(functi" ascii
    $s5 = "return \"BGe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"USf\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}