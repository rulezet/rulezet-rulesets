rule _20160921_e63dc8126cee826e8d941c1665ea92b4_20160921_e67c85fc609b_3160 {
  meta:
    description = "datamaliciousorder - from files 20160921_e63dc8126cee826e8d941c1665ea92b4.js, 20160921_e67c85fc609bef1c06233d9dc655b074.js, 20160921_f6f229e035b34b52398f9d713af3e947.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b87ae77185b5925bd9480daa9d4b74b2291cc670108bf85e0379579434ebff34"
    hash2       = "372b553e13a1b2dacf2c8938d6c7953212ff8112978d88f8aa1425ffa2ef21de"
    hash3       = "dbd2ccfd17959ea084fe518e1748ca4f14e74a14593d7c157b17f4437f4336e3"

  strings:
    $s1 = "s\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(function f" ascii
    $s2 = "urn \"RAi\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"GNm\";})()," ascii
    $s3 = ";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fu" ascii
    $s4 = "){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"USf\";}" ascii
    $s5 = " \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IRn\";})(),(func" ascii
    $s6 = "turn \"TTs\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"Jo\";})(),(" ascii
    $s7 = "on fuck(){return \"Np\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}