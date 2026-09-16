rule _20160921_48b0ab2357d6a2640d84157783389f85_20160921_515291b3ed13_5089 {
  meta:
    description = "datamaliciousorder - from files 20160921_48b0ab2357d6a2640d84157783389f85.js, 20160921_515291b3ed13de9fe2933a326bc71920.js, 20160921_af22e174703ebae0fa1368fd471dba37.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "fee375f08ae5432a47f4a4a8fefed2cbbb6e1484d8914742942e60f703c8f7f0"
    hash2       = "6deef7cfd2f4743f897d0043907a6481545f6a96b01c76c7d81d02348a2a17e0"
    hash3       = "24c1540f49c4fe83a182058f70751619567afa9e8884c1dee7ae13e5fad14a59"

  strings:
    $s1 = "return \"Py\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ot\";})()" ascii
    $s2 = "m\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"USf\";})(),(function " ascii
    $s3 = "Ug\";})(),(function fuck(){return \"Vf\";})(),(function fuck(){return \"KVh\";})(),(function fuck(){return \"UOe\";})(),(functio" ascii
    $s4 = "ction fuck(){return \"MUs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){retur" ascii
    $s5 = "rn \"USf\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"ZWu\";})(),(f" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}