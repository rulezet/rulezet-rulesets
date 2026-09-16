rule _20160921_a96b471e778a8101c168e06727d930fb_20160921_c0cd20cf50e8_3107 {
  meta:
    description = "datamaliciousorder - from files 20160921_a96b471e778a8101c168e06727d930fb.js, 20160921_c0cd20cf50e8d47fdd1303227435227a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f39378ed9c109b442c660bd7c383f0420860e3ac084eca6bb2fd789ead573a49"
    hash2       = "3d34400bc3cfc9235dbf1a201a7f50b72821566d70727533493e74fbeb8a5514"

  strings:
    $s1 = "(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"DRx\";})(),(function fuck()" ascii
    $s2 = "\"IPu\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(funct" ascii
    $s3 = "ion fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return " ascii
    $s4 = "{return \"XFd\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"Xg\";})(" ascii
    $s5 = "urn \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"ZWu\";})(),(" ascii
    $s6 = "r\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Jh\";})(),(function " ascii
    $s7 = "Pc\";})(),(function fuck(){return \"CCb\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"Fv\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}