rule _20160921_91af5c220d1ea27d72d05f472ba8fa16_20160921_99220520e874_1423 {
  meta:
    description = "datamaliciousorder - from files 20160921_91af5c220d1ea27d72d05f472ba8fa16.js, 20160921_99220520e87414c0f2e1267cf4078a22.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d8a5c3b8bd7307238c3f0a133635143674d5db84b7c5615a145a8bea310c68de"
    hash2       = "5b655a405ebc3a6ee1687faec5788f37e732bcfe1afd9f30936ca55a4983a755"

  strings:
    $s1  = "eturn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"CCb\";})()" ascii
    $s2  = "ion fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s3  = ";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fu" ascii
    $s4  = "rn \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Qh\";})(),(fu" ascii
    $s5  = "ion fuck(){return \"DAa\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return" ascii
    $s6  = "n fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s7  = "o\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DWe\";})(),(function" ascii
    $s8  = "rn \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Za\";})(),(f" ascii
    $s9  = "k\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s10 = "CTm\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"AUx\";})(),(functi" ascii
    $s11 = "})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(" ascii
    $s12 = "k(){return \"Ve\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\"" ascii
    $s13 = "uck(){return \"We\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj" ascii
    $s14 = "){return \"Bz\";})()];" fullword ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}