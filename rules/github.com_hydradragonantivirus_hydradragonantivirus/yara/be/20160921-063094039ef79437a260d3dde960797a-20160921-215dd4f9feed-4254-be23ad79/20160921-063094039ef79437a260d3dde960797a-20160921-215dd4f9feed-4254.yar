rule _20160921_063094039ef79437a260d3dde960797a_20160921_215dd4f9feed_4254 {
  meta:
    description = "datamaliciousorder - from files 20160921_063094039ef79437a260d3dde960797a.js, 20160921_215dd4f9feed109fed37b9c9dabdf1c2.js, 20160921_5e9244484429cd897ec88fe97140c29c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "ce1eb4a08b98ec71f6759f87657e36ddf82182025b3e317c586fb55c186b9e6c"
    hash2       = "710f88c7fda95a8d3e0e04de1ffd81606d227d249d76eb0d7fbeba7a0284a86e"
    hash3       = "002e6ee9d0d9e7f54ead7f8981f20be210819f7a75c52e3d1e91de2fd03ada17"

  strings:
    $s1 = "ction fuck(){return \"GNm\";})(),(function fuck(){return \"Bz\";})(),(function fuck(){return \"Tv\";})(),(function fuck(){return" ascii
    $s2 = "return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DHd\";})(),(function fuck(){return \"Ml\";})()" ascii
    $s3 = "(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck()" ascii
    $s4 = "{return \"XCr\";})(),(function fuck(){return \"GWo\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"MOj\";}" ascii
    $s5 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"J" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}