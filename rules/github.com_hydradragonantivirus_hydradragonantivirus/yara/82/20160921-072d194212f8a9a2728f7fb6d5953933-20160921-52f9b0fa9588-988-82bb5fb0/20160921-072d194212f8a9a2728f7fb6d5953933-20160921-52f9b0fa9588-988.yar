rule _20160921_072d194212f8a9a2728f7fb6d5953933_20160921_52f9b0fa9588_988 {
  meta:
    description = "datamaliciousorder - from files 20160921_072d194212f8a9a2728f7fb6d5953933.js, 20160921_52f9b0fa9588abb39dc8ffa331cd277b.js, 20160921_70b567ca258b3c505e14f3c712366f09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73c215f339e3128df4a73ba4ad5b1db80d6620de77bd285fef1d86107197eace"
    hash2       = "7a84827d35b2b189a2872cc9d16d3ab675e3ec50c203690e75cf66ab54056731"
    hash3       = "8cf06551c554a2db81fe1bf37b069b40e558f931913e7d2572bdd18b36f57c73"

  strings:
    $s1  = "\"Xg\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(funct" ascii
    $s2  = "fuck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"USf" ascii
    $s3  = "ction fuck(){return \"UOe\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){retu" ascii
    $s4  = "b\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(function" ascii
    $s5  = "turn \"CTm\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})()" ascii
    $s6  = "f\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s7  = "rn \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(f" ascii
    $s8  = "(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"TTs\";" ascii
    $s9  = "),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){" ascii
    $s10 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"M" ascii
    $s11 = "tion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){retur" ascii
    $s12 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"" ascii
    $s13 = "n fuck(){return \"Ug\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"M" ascii
    $s14 = ")(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"CCb\";})(),(function fuc" ascii
    $s15 = "(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";" ascii
    $s16 = "k(){return \"Xw\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";}" ascii
    $s17 = " fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"X" ascii
    $s18 = "turn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Wo0\";})()," ascii
    $s19 = "eturn \"IOs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}