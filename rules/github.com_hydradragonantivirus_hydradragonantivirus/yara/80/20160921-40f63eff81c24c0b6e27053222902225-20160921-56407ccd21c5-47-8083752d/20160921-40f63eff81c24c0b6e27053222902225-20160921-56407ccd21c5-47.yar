rule _20160921_40f63eff81c24c0b6e27053222902225_20160921_56407ccd21c5_47 {
  meta:
    description = "datamaliciousorder - from files 20160921_40f63eff81c24c0b6e27053222902225.js, 20160921_56407ccd21c5f8f4947d4df222e60442.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6b71d253d7ac7dfb797132caac458cf74b81e67304218edbb764243d89e51bb1"
    hash2       = "bec8a0189f43e097fc0815a0bb39f2df50e4c37c7185ad70b3be3b0d17b8dd32"

  strings:
    $s1  = "unction fuck(){return \"XCr\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){re" ascii
    $s2  = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"" ascii
    $s3  = "return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Cd\";})()" ascii
    $s4  = "fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"C" ascii
    $s5  = "g\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function" ascii
    $s6  = "\"Cd\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(func" ascii
    $s7  = "uck(){return \"MBg\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Dc" ascii
    $s8  = "ion fuck(){return \"TTs\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return " ascii
    $s9  = "ion fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return" ascii
    $s10 = "nction fuck(){return \"Cd\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){retu" ascii
    $s11 = "n fuck(){return \"UOe\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return " ascii
    $s12 = ")(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Zy\";})(),(function fuck" ascii
    $s13 = "})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ot\";})(),(function fuc" ascii
    $s14 = "rn \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(fun" ascii
    $s15 = " \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";})(),(func" ascii
    $s16 = "){return \"TTs\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Fv\";})(" ascii
    $s17 = "Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(functio" ascii
    $s18 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"ADy" ascii
    $s19 = "on fuck(){return \"IKv\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return " ascii
    $s20 = "urn \"IPu\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IRn\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}