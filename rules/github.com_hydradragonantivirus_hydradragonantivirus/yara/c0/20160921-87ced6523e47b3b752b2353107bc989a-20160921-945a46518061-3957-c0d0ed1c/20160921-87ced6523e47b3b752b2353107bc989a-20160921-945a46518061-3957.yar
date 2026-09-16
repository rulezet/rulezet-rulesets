rule _20160921_87ced6523e47b3b752b2353107bc989a_20160921_945a46518061_3957 {
  meta:
    description = "datamaliciousorder - from files 20160921_87ced6523e47b3b752b2353107bc989a.js, 20160921_945a46518061bd8e157aed251e0ffa9e.js, 20160921_9eb4e3262a9bc5c5f03ba0b7b62a3347.js, 20160921_e0f7b2a32a0967097baa59c67369ba3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46c521beb23d37cfa4d60cfcab38c941734971fe3102123b7e4c2813544d39b6"
    hash2       = "cc3d236edb3b45a767b438fa21243a07176d6f5def724e03e45aca76b3127054"
    hash3       = "03bf8e47f97cab996cc7f2d8147659dc1143ccbe1fd09af6b8689379f7263407"
    hash4       = "d527617da74d553b6d56b37f7b101c14280b85e5e40e1f565fe396f8b97b29a2"

  strings:
    $s1 = "\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function " ascii
    $s2 = "eturn \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Hs\";})()," ascii
    $s3 = " fuck(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AD" ascii
    $s4 = " \"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})(),(funct" ascii
    $s5 = "n \"ADy\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(fun" ascii
    $s6 = "(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}