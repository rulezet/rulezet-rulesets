rule _20160921_2111693a6587de2f8afee1834010d572_20160921_b6523fd99592_534 {
  meta:
    description = "datamaliciousorder - from files 20160921_2111693a6587de2f8afee1834010d572.js, 20160921_b6523fd99592b93c7a07e8a0e3a5eaf2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afb04df96413e21fd33fbf65fafdf5fc01cc299acc2cbe099811e60500fbc6d7"
    hash2       = "c7380d8ae5ab67e50f821f2074c7903d887706b91f0b0d3dcfedf5bfbd9a62e0"

  strings:
    $s1  = "uck(){return \"Vf\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"We\"" ascii
    $s2  = "){return \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cs\";})" ascii
    $s3  = "){return \"IPu\";})(),(function fuck(){return \"Yb\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})" ascii
    $s4  = "),(function fuck(){return \"MIl\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"Cd\";})(),(function fuck()" ascii
    $s5  = "turn \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"MOj\";})()" ascii
    $s6  = "})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"SUi\";})(),(function fuck(){return \"RAi\";})(),(function fu" ascii
    $s7  = "rn \"Hs\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"NKq\";})(),(fun" ascii
    $s8  = "})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"IRn\";})(),(function fuc" ascii
    $s9  = "nction fuck(){return \"Vb\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retu" ascii
    $s10 = "n fuck(){return \"Vb\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"P" ascii
    $s11 = "tion fuck(){return \"Cs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return" ascii
    $s12 = "function fuck(){return \"OQr\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){r" ascii
    $s13 = "nction fuck(){return \"ZLd\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){ret" ascii
    $s14 = " \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"FJs\";})(),(func" ascii
    $s15 = "){return \"GNm\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NKq\";" ascii
    $s16 = "fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Py" ascii
    $s17 = "fuck(){return \"Vf\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"NK" ascii
    $s18 = "n \"LGo\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"Ug\";})(),(fun" ascii
    $s19 = "on fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"" ascii
    $s20 = "Vi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Ai\";})(),(function fuck(){return \"ZWu\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}