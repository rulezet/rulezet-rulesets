rule _20160921_87ced6523e47b3b752b2353107bc989a_20160921_8acd2bde0828_5484 {
  meta:
    description = "datamaliciousorder - from files 20160921_87ced6523e47b3b752b2353107bc989a.js, 20160921_8acd2bde0828f30802ece6249f9b9483.js, 20160921_945a46518061bd8e157aed251e0ffa9e.js, 20160921_e0f7b2a32a0967097baa59c67369ba3a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "46c521beb23d37cfa4d60cfcab38c941734971fe3102123b7e4c2813544d39b6"
    hash2       = "9cf59fc7ffd1ec7428d01db709ab365cf4dfe41d386ebb308b8bad860ff941b1"
    hash3       = "cc3d236edb3b45a767b438fa21243a07176d6f5def724e03e45aca76b3127054"
    hash4       = "d527617da74d553b6d56b37f7b101c14280b85e5e40e1f565fe396f8b97b29a2"

  strings:
    $s1 = " \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Jo\";})(),(fun" ascii
    $s2 = "Oe\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s3 = ";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck" ascii
    $s4 = "{return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Vb\";})(" ascii
    $s5 = "Bg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}