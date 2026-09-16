rule _20160921_35d4c12af7a9481959a41a055c396673_20160921_65d76a553954_2869 {
  meta:
    description = "datamaliciousorder - from files 20160921_35d4c12af7a9481959a41a055c396673.js, 20160921_65d76a5539546b98145997b9a44c1a09.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "1c2412951fad30bb8b34aca279acd07c03a437936261b0d90334331b98cf1e99"
    hash2       = "0a1b81d7435f521382a4cec07d80cbc8fe75f2ebac92fb6c4d105b19ec098560"

  strings:
    $s1 = "on fuck(){return \"Py\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"" ascii
    $s2 = "rn \"Wo\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"DRx\";})(),(fun" ascii
    $s3 = "(){return \"Xg\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Xg\";})" ascii
    $s4 = "k(){return \"MBg\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\"" ascii
    $s5 = "\"Hs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Qh\";})(),(funct" ascii
    $s6 = "return \"Ve\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s7 = "UOe\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}