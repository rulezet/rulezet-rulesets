rule _20160921_034dbd5881bc0324f5773d7774d981c4_20160921_17c44cf20b68_754 {
  meta:
    description = "datamaliciousorder - from files 20160921_034dbd5881bc0324f5773d7774d981c4.js, 20160921_17c44cf20b688f3f5be613056d39409e.js, 20160921_4f1da2d661fb97b4733f3fbf35efff6c.js, 20160921_eb8df0d94f3c78c9cec0bde62ab2e57e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "82795298a84df6fa0b0e45225727206f9a173f55589db6b76ab8df4198dc55c7"
    hash2       = "0a10c81cc5c3cc9eb38f73af3b77ed314fed047818a2410613c91431eee6bee1"
    hash3       = "57198460b755f2336c23ed27d26f09514db08ab180e216293a853489286f4ff2"
    hash4       = "768a9ba5aee8702bd0d4c71ccae6016847556423c2ece30b15169aaa7731f27b"

  strings:
    $s1  = "turn \"Wo0\";})(),(function fuck(){return \"ADy\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s2  = "eturn \"OPz\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Zy\";})(),(function fuck(){return \"Jh\";})()," ascii
    $s3  = ")(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"GJx\";})(),(function fuck(){return \"MIl\";})(),(function fuc" ascii
    $s4  = "})(),(function fuck(){return \"USf\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Ug\";})(),(function fuc" ascii
    $s5  = "eturn \"CCb\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"IPu\";})(" ascii
    $s6  = ")(),(function fuck(){return \"XFd\";})(),(function fuck(){return \"AUx\";})(),(function fuck(){return \"DRx\";})(),(function fuc" ascii
    $s7  = ";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"YQt\";})(),(function fu" ascii
    $s8  = "urn \"PDf\";})(),(function fuck(){return \"Np\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"RAi\";})(),(" ascii
    $s9  = "n fuck(){return \"Ik\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"DRx\";})(),(function fuck(){return \"" ascii
    $s10 = "on fuck(){return \"IPu\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"ZLd\";})(),(function fuck(){return " ascii
    $s11 = "unction fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){return \"Ot\";})(),(function fuck(){retu" ascii
    $s12 = "k(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Ik\";}" ascii
    $s13 = "ction fuck(){return \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return" ascii
    $s14 = "fuck(){return \"Ve\";})(),(function fuck(){return \"Mw\";})(),(function fuck(){return \"RAi\";})(),(function fuck(){return \"IPu" ascii
    $s15 = "turn \"MIl\";})(),(function fuck(){return \"FJs\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"DRx\";})()" ascii
    $s16 = "tion fuck(){return \"MUs\";})(),(function fuck(){return \"UOe\";})(),(function fuck(){return \"TTs\";})(),(function fuck(){retur" ascii
    $s17 = "unction fuck(){return \"Za\";})(),(function fuck(){return \"IPu\";})(),(function fuck(){return \"Cd\";})(),(function fuck(){retu" ascii
    $s18 = "urn \"IPu\";})(),(function fuck(){return \"We\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"IPu\";})(),(f" ascii
    $s19 = "ck(){return \"IPu\";})(),(function fuck(){return \"Py\";})(),(function fuck(){return \"YQt\";})(),(function fuck(){return \"Jg\"" ascii
    $s20 = "n fuck(){return \"IPu\";})(),(function fuck(){return \"Ug\";})(),(function fuck(){return \"Na\";})(),(function fuck(){return \"I" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}