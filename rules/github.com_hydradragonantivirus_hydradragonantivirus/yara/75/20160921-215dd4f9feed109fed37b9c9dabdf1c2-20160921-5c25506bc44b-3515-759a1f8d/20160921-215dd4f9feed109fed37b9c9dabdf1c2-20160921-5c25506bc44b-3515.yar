rule _20160921_215dd4f9feed109fed37b9c9dabdf1c2_20160921_5c25506bc44b_3515 {
  meta:
    description = "datamaliciousorder - from files 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js, 20160921_5c25506bc44b50a0c8028dec6521139d.js, 20160921_9e9f1aaa0e051c856253652c93b64496.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"
    hash2       = "b6178db9a292199c6992547ad654bf7056fa7f33310f29988e468f0cad5ed707"
    hash3       = "150de993662365ce2c7407195d1e62da40d5d5ecc67a4a3eb34985123077ada3"

  strings:
    $s1 = "})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Np\";})(),(function fuc" ascii
    $s2 = ",(function fuck(){return \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){r" ascii
    $s3 = "turn \"MBg\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"RAi\";})(),(" ascii
    $s4 = "{return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv\";})" ascii
    $s5 = "turn \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s6 = "on fuck(){return \"LGo\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}