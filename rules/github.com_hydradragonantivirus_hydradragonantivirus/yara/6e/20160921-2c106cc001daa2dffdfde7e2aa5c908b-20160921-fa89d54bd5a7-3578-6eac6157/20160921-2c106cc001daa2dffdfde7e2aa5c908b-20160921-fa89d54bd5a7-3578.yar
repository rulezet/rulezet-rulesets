rule _20160921_2c106cc001daa2dffdfde7e2aa5c908b_20160921_fa89d54bd5a7_3578 {
  meta:
    description = "datamaliciousorder - from files 20160921_2c106cc001daa2dffdfde7e2aa5c908b.js, 20160921_fa89d54bd5a7a27defe09d5a56b5a881.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ca5356b92abf859d45d843749f45e5e06c7d045b4e7ea5d215ab87cdb8c8f66b"
    hash2       = "30f2a7c2562ef79254c8129be50246b9c41eb24f000c8cfbd0f4f8c28b49b00f"

  strings:
    $s1 = "turn \"PDf\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})()," ascii
    $s2 = "(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"IRn\";})(),(function fuck" ascii
    $s3 = "\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Av\";})(),(function fu" ascii
    $s4 = "\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function" ascii
    $s5 = "\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"PDf\";})(),(function " ascii
    $s6 = " fuck(){return \"TTs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"PD" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}