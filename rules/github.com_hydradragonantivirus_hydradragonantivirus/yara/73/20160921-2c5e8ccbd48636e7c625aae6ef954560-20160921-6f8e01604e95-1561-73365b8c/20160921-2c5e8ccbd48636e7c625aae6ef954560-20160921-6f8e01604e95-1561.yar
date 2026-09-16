rule _20160921_2c5e8ccbd48636e7c625aae6ef954560_20160921_6f8e01604e95_1561 {
  meta:
    description = "datamaliciousorder - from files 20160921_2c5e8ccbd48636e7c625aae6ef954560.js, 20160921_6f8e01604e95009c9405a4a9c31cc901.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "70244ca5fa124af09b1f94729567c09dbc52c05035ee7d20cbe87d35e1fe63c8"
    hash2       = "5324b4f5c36c3ebb1567659beec8a89d0c1c954daf56a6131f3aebe46384317b"

  strings:
    $s1  = "UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(funct" ascii
    $s2  = "\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Yk\";})(),(function fuck(){return \"GJx\";})(),(function " ascii
    $s3  = "on fuck(){return \"Zy\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"I" ascii
    $s4  = "urn \"Za\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Jo\";})(),(f" ascii
    $s5  = "(){return \"Ve\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";" ascii
    $s6  = "\"DWe\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Pc\";})(),(funct" ascii
    $s7  = ";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"EHo\";})(),(function fu" ascii
    $s8  = "return \"ZVi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(" ascii
    $s9  = "unction fuck(){return \"Bz\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})()];" fullword ascii
    $s10 = "function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){re" ascii
    $s11 = "return \"TTs\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Wo0\";})" ascii
    $s12 = " \"Na\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"MOj\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}