rule _20160921_abc9044816c2455dc24ac338746b6bd5_20160921_ccb7f2594ec3_5624 {
  meta:
    description = "datamaliciousorder - from files 20160921_abc9044816c2455dc24ac338746b6bd5.js, 20160921_ccb7f2594ec30d819d8973993796faf6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "2bb53920235afb1c2d16f013bc118d1df64065eefc10c1b2b9e7a4b133850850"
    hash2       = "d05110dd6f0ccc6122f08dac231858be0e233eb3cfb596f5f571556d227ab3ef"

  strings:
    $s1 = "k(){return \"CTm\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"FJs\"" ascii
    $s2 = "Oj\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return \"Oh\";})(),(function" ascii
    $s3 = "turn \"Vb\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s4 = "\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"YAv\";})(),(function " ascii
    $s5 = "return \"Xg\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"OQr\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}