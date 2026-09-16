rule _20160921_01613a8c6203a61a61f722629b392b15_20160921_940fdd83fcdf_3168 {
  meta:
    description = "datamaliciousorder - from files 20160921_01613a8c6203a61a61f722629b392b15.js, 20160921_940fdd83fcdf499d0ebc071f779bd880.js, 20160921_a84d89efd5400c906c1132a56b0ef679.js, 20160921_d03dc2f478ae343430b4a6dbcc9d6c08.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7c3ee763f1740e8bc6ded9772aabbe3d3805d8cf2a023e0289a9b8a1a42624b7"
    hash2       = "b73c87ed73bc62067299b13aaa227535cbedafa1a7f74ad02273d1aad3a3449f"
    hash3       = "f3cfecdabdf17d9af410d0fee7ec88844bc361668aca1a114832bd3e515d3456"
    hash4       = "dd1077874fb7f556e5acfe2ff0c2ed6b6c203fcdf442119ca307096446d90cd4"

  strings:
    $s1 = "ion fuck(){return \"Ug\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return " ascii
    $s2 = "z\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MOj\";})(),(function" ascii
    $s3 = "fuck(){return \"MBg\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"Nm" ascii
    $s4 = "ion fuck(){return \"SUi\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"MOj\";})(),(function fuck(){return " ascii
    $s5 = "return \"YQt\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"CCb\";})(" ascii
    $s6 = "nction fuck(){return \"IRn\";})(),(function fuck(){return \"IKv\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}