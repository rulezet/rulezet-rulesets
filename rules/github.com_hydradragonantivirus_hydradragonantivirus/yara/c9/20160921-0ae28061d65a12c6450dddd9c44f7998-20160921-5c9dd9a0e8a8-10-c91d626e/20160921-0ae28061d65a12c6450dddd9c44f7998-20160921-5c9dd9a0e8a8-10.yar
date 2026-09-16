rule _20160921_0ae28061d65a12c6450dddd9c44f7998_20160921_5c9dd9a0e8a8_10 {
  meta:
    description = "datamaliciousorder - from files 20160921_0ae28061d65a12c6450dddd9c44f7998.js, 20160921_5c9dd9a0e8a8b3e5e8713af8aeaa5d59.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2262aefc89b27a9a5b4507f43a6978eafd72ba25a305a11cdeb589d958f0e0a6"
    hash2       = "415a66b711143ada4e334e2da2ea19ca0e94ec191118672a58fa21828a1cd877"

  strings:
    $s1  = "tion fuck(){return \"AUx\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){retur" ascii
    $s2  = "function fuck(){return \"DAa\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){r" ascii
    $s3  = ",(function fuck(){return \"YQt\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck()" ascii
    $s4  = ";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function fuc" ascii
    $s5  = "k(){return \"IPu\";})(),(function fuck(){return \"MIl\";})(),(function fuck(){return \"To\";})(),(function fuck(){return \"EHo\"" ascii
    $s6  = "ck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"Mw\"" ascii
    $s7  = "uck(){return \"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"AUx" ascii
    $s8  = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"XCr\";})(),(funct" ascii
    $s9  = "ion fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return" ascii
    $s10 = "tion fuck(){return \"IPu\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return" ascii
    $s11 = " \"XCr\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s12 = "fuck(){return \"Vb\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IR" ascii
    $s13 = "n \"YQt\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"ADy\";})(),(f" ascii
    $s14 = "uck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"We" ascii
    $s15 = "return \"AUx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"YQt\";})(" ascii
    $s16 = "{return \"Jo\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})(" ascii
    $s17 = "rn \"Et\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s18 = "return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu\";})" ascii
    $s19 = "(){return \"MUs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\"" ascii
    $s20 = "ck(){return \"Wo\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}