rule _20160921_468b13a80ecc75cd21428202c521ca1d_20160921_d56a785468c6_361 {
  meta:
    description = "datamaliciousorder - from files 20160921_468b13a80ecc75cd21428202c521ca1d.js, 20160921_d56a785468c6ab02ba1f7ee3a5eadcdb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d9bb117286f85c2017d3323a8a9f5fd0957993945e9e05ef190746247fc90de3"
    hash2       = "d5ca39f97274b051212868ee58d01e745bb87d0a12198dfdfbeb7c3965cbf540"

  strings:
    $s1  = "on fuck(){return \"ADy\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s2  = "nction fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){retur" ascii
    $s3  = "{return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})" ascii
    $s4  = "urn \"TTs\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})()," ascii
    $s5  = "on fuck(){return \"Cd\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"" ascii
    $s6  = "\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function " ascii
    $s7  = ";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"LGo\";})(),(function fu" ascii
    $s8  = "k(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";" ascii
    $s9  = "urn \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"Np\";})(),(" ascii
    $s10 = "on fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s11 = "ion fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s12 = "ion fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return " ascii
    $s13 = "k(){return \"PDf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\"" ascii
    $s14 = "TTs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(functi" ascii
    $s15 = "m\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";})(),(functio" ascii
    $s16 = "function fuck(){return \"Cd\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){re" ascii
    $s17 = "Vb\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"LGo\";})(),(functio" ascii
    $s18 = "on fuck(){return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return " ascii
    $s19 = " fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"" ascii
    $s20 = "uck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"LG" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}