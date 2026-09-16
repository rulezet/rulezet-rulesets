rule _20160921_1b24f7151bebd3644ff0608076bd2de9_20160921_41f7b3abc606_3462 {
  meta:
    description = "datamaliciousorder - from files 20160921_1b24f7151bebd3644ff0608076bd2de9.js, 20160921_41f7b3abc606ff1ddad7593361eaa449.js, 20160921_759ae57c0ca15acf993d43f7b7e2485d.js, 20160921_7b23bcfdd1289634cd9a4c73f4cbb144.js, 20160921_91424e3b4f105c156aa0fa6f22c2306f.js, 20160921_dc67677da64e0c03fb55538663264839.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33f3c9ce370f10b37d492f9d2cda8602f5d90eb1573205e1a4da03da8066ff45"
    hash2       = "53e06a7234c6522ba26a61e46d13312e1063594b0e33bec9fae49d2dc4b77c28"
    hash3       = "d9d1c0189a6de533e712d41961659591f07faec880d17e164eed8e8084710d25"
    hash4       = "7a94fbc46ac51a544406f9a59bf405cd1e19e8e6681d7feacbc81e5ab7d4a50b"
    hash5       = "b4a035e38404ad09be99953980865cdbcda5dd05b664dff96722afb53b0c9e29"
    hash6       = "0421d641ee833363b2481952ecbaff1400ca62443adb847ffe03bed95e4077f8"

  strings:
    $s1 = ",(function fuck(){return \"IPu\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"OQr\";})(),(function fuck()" ascii
    $s2 = "rn \"ADy\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s3 = "n \"IKv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"UOe\";})(),(f" ascii
    $s4 = " \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"GNm\";})(),(fun" ascii
    $s5 = "})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck" ascii
    $s6 = "Pu\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}