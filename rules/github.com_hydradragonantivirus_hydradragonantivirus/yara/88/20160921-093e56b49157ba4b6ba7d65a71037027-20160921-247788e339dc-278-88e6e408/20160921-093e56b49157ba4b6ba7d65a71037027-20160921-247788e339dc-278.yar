rule _20160921_093e56b49157ba4b6ba7d65a71037027_20160921_247788e339dc_278 {
  meta:
    description = "datamaliciousorder - from files 20160921_093e56b49157ba4b6ba7d65a71037027.js, 20160921_247788e339dc74bbc88f76ce47a9ad41.js, 20160921_9addbf25729a1d4b42c35fbdfee2e294.js, 20160921_d88b1be24c583b3513de141e173a825f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "668a3627d0c7aef7745fe8887088d7f4ec88fb6a39c2470772085711e7db7c98"
    hash2       = "8d162c56b101895f4375e57c40971578d34e8dd1fdd076db93d245dcdade7a48"
    hash3       = "ec349891ac6c40b31c9f4aa62af04d8c399b64bf3db62ab4c615e3eb0931f1e6"
    hash4       = "be789e0d16008ea27a540870c4b670071885fb31e3c8c6ebfb775def3b30a551"

  strings:
    $s1  = "\"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s2  = "turn \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})()" ascii
    $s3  = "ck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"YQt" ascii
    $s4  = "k(){return \"TTs\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"YQt\"" ascii
    $s5  = "n \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"AUx\";})(),(fu" ascii
    $s6  = "RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"YQt\";})(),(funct" ascii
    $s7  = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"USf\";})(),(function fuck(){ret" ascii
    $s8  = "urn \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"AUx\";})(),(" ascii
    $s9  = "(){return \"MUs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"Ug\";" ascii
    $s10 = "function fuck(){return \"YQt\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){re" ascii
    $s11 = "ction fuck(){return \"ADy\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){retu" ascii
    $s12 = "b\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"IRn\";})(),(function" ascii
    $s13 = "n \"Av\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"SUi\";})(),(fun" ascii
    $s14 = "unction fuck(){return \"AUx\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){re" ascii
    $s15 = " \"AUx\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(fu" ascii
    $s16 = "ck(){return \"AUx\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg" ascii
    $s17 = "MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";})(),(functio" ascii
    $s18 = "{return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";}" ascii
    $s19 = "Rx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Vb\";})(),(functio" ascii
    $s20 = "rn \"ZLd\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}