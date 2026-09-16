rule _20160921_2111693a6587de2f8afee1834010d572_20160921_b6523fd99592_1458 {
  meta:
    description = "datamaliciousorder - from files 20160921_2111693a6587de2f8afee1834010d572.js, 20160921_b6523fd99592b93c7a07e8a0e3a5eaf2.js, 20160921_e6977bb87c752a8f54937489e4d135c8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "afb04df96413e21fd33fbf65fafdf5fc01cc299acc2cbe099811e60500fbc6d7"
    hash2       = "c7380d8ae5ab67e50f821f2074c7903d887706b91f0b0d3dcfedf5bfbd9a62e0"
    hash3       = "b2ce1297f179a619d69aa5fa99bb53216eba4d290e545dddda5d0a561f760ec0"

  strings:
    $s1  = "on fuck(){return \"Za\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii
    $s2  = "ion fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return " ascii
    $s3  = "on fuck(){return \"MUs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return " ascii
    $s4  = " fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"J" ascii
    $s5  = "uck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"DWe" ascii
    $s6  = "{return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Dc\";})()" ascii
    $s7  = "nction fuck(){return \"LLv\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){retu" ascii
    $s8  = "(function fuck(){return \"UXf\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){r" ascii
    $s9  = "{return \"IKv\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})" ascii
    $s10 = "n fuck(){return \"Py\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"" ascii
    $s11 = " \"OQr\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(func" ascii
    $s12 = "urn \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Nm\";})(),(fu" ascii
    $s13 = ",(function fuck(){return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}