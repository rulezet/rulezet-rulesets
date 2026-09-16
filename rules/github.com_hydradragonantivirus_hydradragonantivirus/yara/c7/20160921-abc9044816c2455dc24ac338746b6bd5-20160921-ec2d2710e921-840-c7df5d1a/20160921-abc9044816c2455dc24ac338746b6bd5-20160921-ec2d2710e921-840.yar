rule _20160921_abc9044816c2455dc24ac338746b6bd5_20160921_ec2d2710e921_840 {
  meta:
    description = "datamaliciousorder - from files 20160921_abc9044816c2455dc24ac338746b6bd5.js, 20160921_ec2d2710e9217c2f295a4b410a623d5d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bb53920235afb1c2d16f013bc118d1df64065eefc10c1b2b9e7a4b133850850"
    hash2       = "efabdabbb3a7d8e1d713826868acadadd9ab03b4cb57f3799d6add11f212fdd9"

  strings:
    $s1  = " \"OQr\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(fun" ascii
    $s2  = "on fuck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"" ascii
    $s3  = "\"Wo0\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Ar\";})(),(funct" ascii
    $s4  = "nction fuck(){return \"Ai\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){retu" ascii
    $s5  = "\"ADy\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"MOj\";})(),(fun" ascii
    $s6  = "ction fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})(),(function fuck(){return" ascii
    $s7  = "n fuck(){return \"Yk\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s8  = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){retur" ascii
    $s9  = "unction fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"DAa\";})(),(function fuck(){re" ascii
    $s10 = "tion fuck(){return \"KVh\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s11 = "turn \"Ml\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Ai\";})(),(f" ascii
    $s12 = "k(){return \"LGo\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Hs\";}" ascii
    $s13 = "urn \"EHo\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(" ascii
    $s14 = "eturn \"FJs\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Nm\";})()," ascii
    $s15 = "Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"Nm\";})(),(functio" ascii
    $s16 = "rn \"Dc\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(),(fu" ascii
    $s17 = "uck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"Jo\"" ascii
    $s18 = "){return \"Ar\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ve\";})(" ascii
    $s19 = "tion fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return" ascii
    $s20 = "PDf\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}