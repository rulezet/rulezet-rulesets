rule _20160921_06a7c56eaf19048ede06f33b655f2bc5_20160921_5cc1e2fc6d6f_3263 {
  meta:
    description = "datamaliciousorder - from files 20160921_06a7c56eaf19048ede06f33b655f2bc5.js, 20160921_5cc1e2fc6d6fe845510388bfa2dd1826.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "3971833c2ab49de293c47181e999db88e5cad0eaddc5aa38a2516eeac1cab29d"
    hash2       = "8517cbcc9f90e7835f4bbbef31cd3779f0298cca7076dd98e48fb69d359f4820"

  strings:
    $s1 = "return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Dc\";})()," ascii
    $s2 = "urn \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"Et\";})(),(" ascii
    $s3 = "(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"YQt\";})(),(function fuck" ascii
    $s4 = "{return \"YQt\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})" ascii
    $s5 = ",(function fuck(){return \"ADy\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"NKq\";})(),(function fuck()" ascii
    $s6 = "return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}