rule _20160921_11906f10ee01a55012f649f6f86dd24b_20160921_8881f4de1f94_309 {
  meta:
    description = "datamaliciousorder - from files 20160921_11906f10ee01a55012f649f6f86dd24b.js, 20160921_8881f4de1f94ec992ad3832b292063a8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f7e3d843ddea21ba91cad5bd21d3e536f69426d4c4c5a060bbfe7f1f967bda27"
    hash2       = "708c7205c47d660aa1d234233e251c8ac7e8deb0f5606bd3240bfd2a1f736633"

  strings:
    $s1  = "rn \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii
    $s2  = " fuck(){return \"MBg\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"R" ascii
    $s3  = "(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\"" ascii
    $s4  = "ion fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return " ascii
    $s5  = "ction fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){retu" ascii
    $s6  = "rn \"RAi\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s7  = "rn \"PDf\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(f" ascii
    $s8  = " fuck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"C" ascii
    $s9  = "urn \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(" ascii
    $s10 = "fuck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"I" ascii
    $s11 = "ck(){return \"PDf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq" ascii
    $s12 = "urn \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LGo\";})()," ascii
    $s13 = ";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuc" ascii
    $s14 = "urn \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(f" ascii
    $s15 = "ck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"We\";" ascii
    $s16 = "ion fuck(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return" ascii
    $s17 = ")(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"IRn\";})(),(function fuck" ascii
    $s18 = "n \"Wo0\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IPu\";})(),(fu" ascii
    $s19 = "nction fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){ret" ascii
    $s20 = "return \"MBg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}