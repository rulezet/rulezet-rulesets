rule _20160921_48b0ab2357d6a2640d84157783389f85_20160921_515291b3ed13_1714 {
  meta:
    description = "datamaliciousorder - from files 20160921_48b0ab2357d6a2640d84157783389f85.js, 20160921_515291b3ed13de9fe2933a326bc71920.js, 20160921_5d253f3fb31881c7c27141d74e02cacb.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fee375f08ae5432a47f4a4a8fefed2cbbb6e1484d8914742942e60f703c8f7f0"
    hash2       = "6deef7cfd2f4743f897d0043907a6481545f6a96b01c76c7d81d02348a2a17e0"
    hash3       = "ae85fe56260e8c9a1243da145f7594a08ac59bd50027af5e54b6d04e82f44e88"

  strings:
    $s1  = "})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"RAi\";})(),(function fuck" ascii
    $s2  = "b\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ZWu\";})(),(function" ascii
    $s3  = "fuck(){return \"TTs\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"U" ascii
    $s4  = "return \"ADy\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Et\";})(),(function fuck(){return \"DAa\";})(" ascii
    $s5  = "ck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Yk\"" ascii
    $s6  = "n fuck(){return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"" ascii
    $s7  = "turn \"TTs\";})(),(function fuck(){return \"Qh\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"AUx\";})()," ascii
    $s8  = "\"Fv\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ZWu\";})(),(funct" ascii
    $s9  = "rn \"GJx\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"ADy\";})(),(" ascii
    $s10 = ")(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ZWu\";})(),(function fuck" ascii
    $s11 = " \"AUx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Cd\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}