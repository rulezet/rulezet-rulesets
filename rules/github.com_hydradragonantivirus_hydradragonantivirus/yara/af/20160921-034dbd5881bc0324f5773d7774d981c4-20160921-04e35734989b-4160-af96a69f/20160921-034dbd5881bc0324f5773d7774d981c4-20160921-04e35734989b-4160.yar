rule _20160921_034dbd5881bc0324f5773d7774d981c4_20160921_04e35734989b_4160 {
  meta:
    description = "datamaliciousorder - from files 20160921_034dbd5881bc0324f5773d7774d981c4.js, 20160921_04e35734989b05b680234592aacc01ad.js, 20160921_17c44cf20b688f3f5be613056d39409e.js, 20160921_2b890152a974503e2dcd034f2b4084b0.js, 20160921_4e6afd7ea6614e65fabdc4281ed92b34.js, 20160921_4f1da2d661fb97b4733f3fbf35efff6c.js, 20160921_abc9044816c2455dc24ac338746b6bd5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82795298a84df6fa0b0e45225727206f9a173f55589db6b76ab8df4198dc55c7"
    hash2       = "6553e0c768ddf3ba1bc09a83e90e280707f7613c13bcc2b4bae89c9a347ee2f5"
    hash3       = "0a10c81cc5c3cc9eb38f73af3b77ed314fed047818a2410613c91431eee6bee1"
    hash4       = "74075b371da5cc0281ecbcdc311542bcafb1a5daba17f8b3fafc81a88714f625"
    hash5       = "2af9fdbe6325bb563ca12f506f0bc07133a1951c94c5f0bd5dced26a493d8e18"
    hash6       = "57198460b755f2336c23ed27d26f09514db08ab180e216293a853489286f4ff2"
    hash7       = "2bb53920235afb1c2d16f013bc118d1df64065eefc10c1b2b9e7a4b133850850"

  strings:
    $s1 = "ction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return" ascii
    $s2 = "})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"OQr\";})(),(function fuck(){return \"Ve\";})(),(function fuck" ascii
    $s3 = "urn \"Yk\";})(),(function fuck(){return \"Wo0\";})(),(function fuck(){return \"OPz\";})(),(function fuck(){return \"IPu\";})(),(" ascii
    $s4 = "ion fuck(){return \"CTm\";})(),(function fuck(){return \"CTm\";})(),(function fuck(){return \"XCr\";})(),(function fuck(){return" ascii
    $s5 = "return \"Nm\";})(),(function fuck(){return \"MUs\";})(),(function fuck(){return \"Pc\";})(),(function fuck(){return \"XHj\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}