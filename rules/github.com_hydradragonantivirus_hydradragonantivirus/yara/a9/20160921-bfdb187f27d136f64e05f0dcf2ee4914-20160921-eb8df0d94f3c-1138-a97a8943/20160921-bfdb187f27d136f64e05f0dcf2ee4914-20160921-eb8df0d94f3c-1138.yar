rule _20160921_bfdb187f27d136f64e05f0dcf2ee4914_20160921_eb8df0d94f3c_1138 {
  meta:
    description = "datamaliciousorder - from files 20160921_bfdb187f27d136f64e05f0dcf2ee4914.js, 20160921_eb8df0d94f3c78c9cec0bde62ab2e57e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cbf2173e7b067de6ce6bf189ba38c78f3f0d97a7e6685c0191e08885badfeb3e"
    hash2       = "768a9ba5aee8702bd0d4c71ccae6016847556423c2ece30b15169aaa7731f27b"

  strings:
    $s1  = "n \"Dc\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"ZWu\";})(),(fun" ascii
    $s2  = "),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(" ascii
    $s3  = "function fuck(){return \"USf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){r" ascii
    $s4  = "rn \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(f" ascii
    $s5  = "nction fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){retu" ascii
    $s6  = "on fuck(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"" ascii
    $s7  = "rn \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(f" ascii
    $s8  = ";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(function fuc" ascii
    $s9  = "nction fuck(){return \"Ar\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){retu" ascii
    $s10 = "turn \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"PDf\";})()" ascii
    $s11 = "k(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"DHd" ascii
    $s12 = " fuck(){return \"RAi\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"I" ascii
    $s13 = "on fuck(){return \"Pc\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return " ascii
    $s14 = "(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"Ai\";})(),(function fuck()" ascii
    $s15 = "Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Vb\";})(),(functio" ascii
    $s16 = "on fuck(){return \"Yk\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s17 = "on fuck(){return \"DHd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}