rule _20160921_940fdd83fcdf499d0ebc071f779bd880_20160921_e3aa4388897e_5558 {
  meta:
    description = "datamaliciousorder - from files 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_e3aa4388897e55faa45b78b5304a0796.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash2       = "2891f4105f11c496e2a838e51e47950b803da8c03fe0cd132c2ad23839c0ca37"

  strings:
    $s1 = "on fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return " ascii
    $s2 = "eturn \"IPu\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return \"Jg\";})(),(function fuck(){return \"GNm\";})()" ascii
    $s3 = "n \"Mw\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s4 = "eturn \"DRx\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"IPu\";})()" ascii
    $s5 = ";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"QTc\";})(),(function fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}