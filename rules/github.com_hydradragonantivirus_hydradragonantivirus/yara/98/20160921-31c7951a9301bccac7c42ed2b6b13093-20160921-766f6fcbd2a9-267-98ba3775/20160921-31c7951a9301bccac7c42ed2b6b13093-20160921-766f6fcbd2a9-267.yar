rule _20160921_31c7951a9301bccac7c42ed2b6b13093_20160921_766f6fcbd2a9_267 {
  meta:
    description = "datamaliciousorder - from files 20160921_31c7951a9301bccac7c42ed2b6b13093.js, 20160921_766f6fcbd2a94a55747a3f5b9a204b0e.js, 20160921_e2cf0a7330632dcfdd75ef1c324289b4.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "170c53b6198c4ffe293d40953d3f705212182666ee02a10f7b562b4a16af7559"
    hash2       = "7ac34bd929ce60a874936fef08adcce78783c70441a9eff1cd392604bcf45ff7"
    hash3       = "ad7238fc2ad12cca7ecf6bccdbe5df095519b23408e1a1f63f4ad19a50469d2e"

  strings:
    $s1  = "(){return \"IKv\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"RAi\"" ascii
    $s2  = "{return \"YQt\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"LGo\";})" ascii
    $s3  = "(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";" ascii
    $s4  = "nction fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retur" ascii
    $s5  = "uck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Cd" ascii
    $s6  = "n \"Np\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})(),(fun" ascii
    $s7  = "urn \"PDf\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"GNm\";})()," ascii
    $s8  = "urn \"ZLd\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"ZVi\";})(),(function fuck(){return \"Vb\";})(),(" ascii
    $s9  = "turn \"ADy\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"LGo\";})()" ascii
    $s10 = "Go\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s11 = "k(){return \"PDf\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"NKq" ascii
    $s12 = "i\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"NKq\";})(),(function " ascii
    $s13 = "n \"OQr\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"Na\";})(),(fu" ascii
    $s14 = "rn \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(" ascii
    $s15 = "ion fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return " ascii
    $s16 = "eturn \"PDf\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Cd\";})()," ascii
    $s17 = "k(){return \"RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"USf" ascii
    $s18 = "{return \"IKv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"GNm\";}" ascii
    $s19 = "urn \"PDf\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(" ascii
    $s20 = "ck(){return \"UOe\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}