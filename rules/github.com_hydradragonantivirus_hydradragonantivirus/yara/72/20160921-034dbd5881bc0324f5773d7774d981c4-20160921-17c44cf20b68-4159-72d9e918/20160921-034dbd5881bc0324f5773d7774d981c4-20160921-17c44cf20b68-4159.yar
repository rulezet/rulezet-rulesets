rule _20160921_034dbd5881bc0324f5773d7774d981c4_20160921_17c44cf20b68_4159 {
  meta:
    description = "datamaliciousorder - from files 20160921_034dbd5881bc0324f5773d7774d981c4.js, 20160921_17c44cf20b688f3f5be613056d39409e.js, 20160921_42353ce257534ed06a8c73cebdde12dc.js, 20160921_4f1da2d661fb97b4733f3fbf35efff6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82795298a84df6fa0b0e45225727206f9a173f55589db6b76ab8df4198dc55c7"
    hash2       = "0a10c81cc5c3cc9eb38f73af3b77ed314fed047818a2410613c91431eee6bee1"
    hash3       = "68261e17878fc3b618b0fec34ae97fb6fea1090c52fff206192cb972d23b2b35"
    hash4       = "57198460b755f2336c23ed27d26f09514db08ab180e216293a853489286f4ff2"

  strings:
    $s1 = "k(){return \"IKv\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"Vb\";" ascii
    $s2 = "u\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"UOe\";})(),(function" ascii
    $s3 = "uck(){return \"USf\";})(),(function fuck(){return \"Jo\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"IKv" ascii
    $s4 = "\"MBg\";})(),(function fuck(){return \"Vb\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"RAi\";})(),(func" ascii
    $s5 = "\"UOe\";})(),(function fuck(){return \"Hs\";})(),(function fuck(){return \"IRn\";})(),(function fuck(){return \"MBg\";})(),(func" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}