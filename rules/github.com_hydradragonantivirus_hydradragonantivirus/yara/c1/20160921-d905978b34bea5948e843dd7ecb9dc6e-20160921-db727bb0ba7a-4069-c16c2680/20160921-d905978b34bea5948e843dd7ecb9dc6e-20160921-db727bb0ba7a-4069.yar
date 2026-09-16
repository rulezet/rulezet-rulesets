rule _20160921_d905978b34bea5948e843dd7ecb9dc6e_20160921_db727bb0ba7a_4069 {
  meta:
    description = "datamaliciousorder - from files 20160921_d905978b34bea5948e843dd7ecb9dc6e.js, 20160921_db727bb0ba7a4addd64ea2ef7f7475f0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8110e9072a75f1960f23243cc11d3c233a350d63360d8006cad608a2fb81e0b3"
    hash2       = "12f83f9c7412fb362b5d1e9209d11bdf03d66f9505ff4d2247b8a85f687d4cb8"

  strings:
    $s1 = ")(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"IRn\";})(),(function fuc" ascii
    $s2 = "turn \"RAi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"GNm\";})()," ascii
    $s3 = " fuck(){return \"OQr\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"U" ascii
    $s4 = "fuck(){return \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"C" ascii
    $s5 = "rn \"IPu\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"RAi\";})(),(f" ascii
    $s6 = "RAi\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}