rule _20160921_5a42d0e1880d178346694a30bc112076_20160921_e53844f4bb18_5236 {
  meta:
    description = "datamaliciousorder - from files 20160921_5a42d0e1880d178346694a30bc112076.js, 20160921_e53844f4bb18305322896332fbd017e8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca8e81eec437e87b27dedb202751f13e736aa092e78fffde5fbf40616f2e3738"
    hash2       = "b8484bab412a47fffb0a694f32ca5de3480841bd1c0806d0a7e6e86dfd21de6c"

  strings:
    $s1 = "Cb\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"Jo\";})(),(function" ascii
    $s2 = "n fuck(){return \"Za\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"" ascii
    $s3 = "tion fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return" ascii
    $s4 = "fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"OP" ascii
    $s5 = "fuck(){return \"USf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}