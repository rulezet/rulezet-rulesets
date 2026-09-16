rule _20160921_04e35734989b05b680234592aacc01ad_20160921_2b890152a974_4203 {
  meta:
    description = "datamaliciousorder - from files 20160921_04e35734989b05b680234592aacc01ad.js, 20160921_2b890152a974503e2dcd034f2b4084b0.js, 20160921_4e6afd7ea6614e65fabdc4281ed92b34.js, 20160921_9e9f1aaa0e051c856253652c93b64496.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "6553e0c768ddf3ba1bc09a83e90e280707f7613c13bcc2b4bae89c9a347ee2f5"
    hash2       = "74075b371da5cc0281ecbcdc311542bcafb1a5daba17f8b3fafc81a88714f625"
    hash3       = "2af9fdbe6325bb563ca12f506f0bc07133a1951c94c5f0bd5dced26a493d8e18"
    hash4       = "150de993662365ce2c7407195d1e62da40d5d5ecc67a4a3eb34985123077ada3"

  strings:
    $s1 = ")(),(function fuck(){return \"We\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"MOj\";})(),(function fuck(" ascii
    $s2 = "IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Jh\";})(),(function fuck(){return \"MOj\";})(),(functio" ascii
    $s3 = "})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Py\";})(),(function fuc" ascii
    $s4 = " fuck(){return \"GJx\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"L" ascii
    $s5 = "turn \"MOj\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"ILp\";})(),(function fuck(){return \"GNm\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}