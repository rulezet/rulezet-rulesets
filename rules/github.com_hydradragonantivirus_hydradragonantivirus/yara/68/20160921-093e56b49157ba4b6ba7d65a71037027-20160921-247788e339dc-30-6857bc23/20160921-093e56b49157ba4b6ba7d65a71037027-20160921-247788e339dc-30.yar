rule _20160921_093e56b49157ba4b6ba7d65a71037027_20160921_247788e339dc_30 {
  meta:
    description = "datamaliciousorder - from files 20160921_093e56b49157ba4b6ba7d65a71037027.js, 20160921_247788e339dc74bbc88f76ce47a9ad41.js, 20160921_9addbf25729a1d4b42c35fbdfee2e294.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "668a3627d0c7aef7745fe8887088d7f4ec88fb6a39c2470772085711e7db7c98"
    hash2       = "8d162c56b101895f4375e57c40971578d34e8dd1fdd076db93d245dcdade7a48"
    hash3       = "ec349891ac6c40b31c9f4aa62af04d8c399b64bf3db62ab4c615e3eb0931f1e6"

  strings:
    $s1  = ";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"ZLd\";})(),(function f" ascii
    $s2  = ";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ve\";})(),(function fuc" ascii
    $s3  = "){return \"Dc\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";}" ascii
    $s4  = "eturn \"IPu\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"Np\";})()," ascii
    $s5  = "n \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Wo0\";})(),(fu" ascii
    $s6  = "urn \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Qh\";})(),(f" ascii
    $s7  = " fuck(){return \"YQt\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"" ascii
    $s8  = "s\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function" ascii
    $s9  = "turn \"IPu\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"GNm\";})()" ascii
    $s10 = "rn \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"AUx\";})(),(" ascii
    $s11 = "urn \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"UXf\";})(),(" ascii
    $s12 = " fuck(){return \"Ot\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"IRn" ascii
    $s13 = "fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"EH" ascii
    $s14 = "ction fuck(){return \"Oh\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return " ascii
    $s15 = "(),(function fuck(){return \"Av\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Nm\";})(),(function fuck()" ascii
    $s16 = "Jx\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(functio" ascii
    $s17 = "ion fuck(){return \"YQt\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return" ascii
    $s18 = "b\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"IRn\";})(),(functio" ascii
    $s19 = "){return \"IPu\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";" ascii
    $s20 = "){return \"RAi\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}