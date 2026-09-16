rule _20160921_034dbd5881bc0324f5773d7774d981c4_20160921_17c44cf20b68_1438 {
  meta:
    description = "datamaliciousorder - from files 20160921_034dbd5881bc0324f5773d7774d981c4.js, 20160921_17c44cf20b688f3f5be613056d39409e.js, 20160921_26653257e0da59c861fc658d3bccdafd.js, 20160921_4f1da2d661fb97b4733f3fbf35efff6c.js, 20160921_eb8df0d94f3c78c9cec0bde62ab2e57e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82795298a84df6fa0b0e45225727206f9a173f55589db6b76ab8df4198dc55c7"
    hash2       = "0a10c81cc5c3cc9eb38f73af3b77ed314fed047818a2410613c91431eee6bee1"
    hash3       = "1dff3cae9c135714cad3879ac1ef904841ec9264e3448106fbedd3b57ca11e97"
    hash4       = "57198460b755f2336c23ed27d26f09514db08ab180e216293a853489286f4ff2"
    hash5       = "768a9ba5aee8702bd0d4c71ccae6016847556423c2ece30b15169aaa7731f27b"

  strings:
    $s1  = "Vi\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"TTs\";})(),(functio" ascii
    $s2  = "uck(){return \"IOs\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"XCr" ascii
    $s3  = "nction fuck(){return \"Nm\";})(),(function fuck(){return \"Ve\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return" ascii
    $s4  = "on fuck(){return \"To\";})(),(function fuck(){return \"Wo\";})(),(function fuck(){return \"Av\";})(),(function fuck(){return \"J" ascii
    $s5  = "nction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){retur" ascii
    $s6  = "(function fuck(){return \"Qh\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){re" ascii
    $s7  = "Ot\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"MIl\";})(),(functio" ascii
    $s8  = "ion fuck(){return \"USf\";})(),(function fuck(){return \"MBg\";})(),(function fuck(){return \"Xw\";})(),(function fuck(){return " ascii
    $s9  = "n \"LGo\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IPu\";})(),(fun" ascii
    $s10 = "{return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"YAv\";})(" ascii
    $s11 = " \"ZVi\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"GJx\";})(),(fu" ascii
    $s12 = "on fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Nm\";})(),(function fuck(){return \"" ascii
    $s13 = "function fuck(){return \"Vb\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"NKq\";})(),(function fuck(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}