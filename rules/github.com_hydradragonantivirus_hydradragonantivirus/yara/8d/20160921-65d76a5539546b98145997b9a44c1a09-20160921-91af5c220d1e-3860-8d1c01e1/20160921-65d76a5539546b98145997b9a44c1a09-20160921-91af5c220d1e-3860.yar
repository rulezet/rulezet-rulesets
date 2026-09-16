rule _20160921_65d76a5539546b98145997b9a44c1a09_20160921_91af5c220d1e_3860 {
  meta:
    description = "datamaliciousorder - from files 20160921_65d76a5539546b98145997b9a44c1a09.js, 20160921_91af5c220d1ea27d72d05f472ba8fa16.js, 20160921_99220520e87414c0f2e1267cf4078a22.js, 20160921_d35b8ea76f45dbc35f302f0ac5357655.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "0a1b81d7435f521382a4cec07d80cbc8fe75f2ebac92fb6c4d105b19ec098560"
    hash2       = "d8a5c3b8bd7307238c3f0a133635143674d5db84b7c5615a145a8bea310c68de"
    hash3       = "5b655a405ebc3a6ee1687faec5788f37e732bcfe1afd9f30936ca55a4983a755"
    hash4       = "9dcc5774827243903cab74a4e9a77a6ec68f90a8c6ce60869e9bc7d13bcac921"

  strings:
    $s1 = "{return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})()" ascii
    $s2 = ")(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(" ascii
    $s3 = "g\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"ADy\";})(),(function " ascii
    $s4 = "\"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IRn\";})(),(funct" ascii
    $s5 = "rn \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jo\";})(),(fu" ascii
    $s6 = "Dy\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}