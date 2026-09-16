rule _20160921_034dbd5881bc0324f5773d7774d981c4_20160921_17c44cf20b68_3194 {
  meta:
    description = "datamaliciousorder - from files 20160921_034dbd5881bc0324f5773d7774d981c4.js, 20160921_17c44cf20b688f3f5be613056d39409e.js, 20160921_4f1da2d661fb97b4733f3fbf35efff6c.js, 20160921_a2f8f3f44ef6a3341feac8fb57e829ce.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82795298a84df6fa0b0e45225727206f9a173f55589db6b76ab8df4198dc55c7"
    hash2       = "0a10c81cc5c3cc9eb38f73af3b77ed314fed047818a2410613c91431eee6bee1"
    hash3       = "57198460b755f2336c23ed27d26f09514db08ab180e216293a853489286f4ff2"
    hash4       = "619e82812300e58dd7cd06b8fbcf2f7e3f6757812cc075603c82363ab6481758"

  strings:
    $s1 = "{return \"Zy\";})(),(function fuck(){return \"YAv\";})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"NKq\";})" ascii
    $s2 = ")(),(function fuck(){return \"TTs\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"YQt\";})(),(function fuc" ascii
    $s3 = "nction fuck(){return \"DRx\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){retu" ascii
    $s4 = "turn \"Ik\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(" ascii
    $s5 = "(){return \"TTs\";})(),(function fuck(){return \"Oh\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"IPu\";" ascii
    $s6 = "\"Jo\";})(),(function fuck(){return \"PDf\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){return \"GNm\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}