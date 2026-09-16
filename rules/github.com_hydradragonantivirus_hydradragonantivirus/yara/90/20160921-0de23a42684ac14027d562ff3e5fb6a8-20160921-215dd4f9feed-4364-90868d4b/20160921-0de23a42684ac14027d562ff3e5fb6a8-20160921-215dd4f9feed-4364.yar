rule _20160921_0de23a42684ac14027d562ff3e5fb6a8_20160921_215dd4f9feed_4364 {
  meta:
    description = "datamaliciousorder - from files 20160921_0de23a42684ac14027d562ff3e5fb6a8.js, 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7237be0906b854ec3890943cde0c9a731117b836078be4256fe37413dd372a66"
    hash2       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"

  strings:
    $s1 = "ction fuck(){return \"Jo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return" ascii
    $s2 = "),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){" ascii
    $s3 = "IPu\";})(),(function fuck(){return \"DWe\";})(),(function fuck(){return \"EHo\";})(),(function fuck(){return \"IPu\";})(),(funct" ascii
    $s4 = "\"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Na\";})(),(functi" ascii
    $s5 = "ion fuck(){return \"DWe\";})(),(function fuck(){return \"Ar\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}