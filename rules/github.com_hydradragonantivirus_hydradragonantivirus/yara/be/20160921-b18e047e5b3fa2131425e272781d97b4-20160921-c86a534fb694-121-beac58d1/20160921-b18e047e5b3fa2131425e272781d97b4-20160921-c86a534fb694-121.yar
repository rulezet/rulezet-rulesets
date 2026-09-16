rule _20160921_b18e047e5b3fa2131425e272781d97b4_20160921_c86a534fb694_121 {
  meta:
    description = "datamaliciousorder - from files 20160921_b18e047e5b3fa2131425e272781d97b4.js, 20160921_c86a534fb694b7c269b48a9dc32f8a87.js, 20160921_d6e5226f779c21f4fc4b67aeddca2869.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "033421645eb5cdfdccc02e470b5304f91fa62121d1e117f1aebca723440cec70"
    hash2       = "921432f56757fdaa414b8b2f729fdd46e41c954a0a96b706c646c1d5ab09e5cb"
    hash3       = "42ec93947d9a157ccd37a3c75c7a06b75fa756fee925b759536deb0993f07a5b"

  strings:
    $s1  = "00(){return \"MMz\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\"" ascii
    $s2  = "\"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"OUx\";})(),(funct" ascii
    $s3  = "000(){return \"Wy\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\"" ascii
    $s4  = "tion f000(){return \"Kw\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return" ascii
    $s5  = "eturn \"Qz\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"RPt\";})()," ascii
    $s6  = "urn \"ZGq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"Do\";})(),(fu" ascii
    $s7  = "000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Tn" ascii
    $s8  = "l\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s9  = "n \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"DYx\";})(),(fun" ascii
    $s10 = "n \"TKl\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(fun" ascii
    $s11 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Yz\";})(),(function f000(){retu" ascii
    $s12 = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"ZIi\";})(),(f" ascii
    $s13 = "n f000(){return \"HJm\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"BMj\";})(),(function f000(){return " ascii
    $s14 = "turn \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Qj\";})()," ascii
    $s15 = " \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"TRc\";})(),(func" ascii
    $s16 = "turn \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"GGn\";})()," ascii
    $s17 = "unction f000(){return \"Nx\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Oe\";})(),(function f000(){retu" ascii
    $s18 = "return \"KDh\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Kw\";})()," ascii
    $s19 = "on f000(){return \"Vj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"G" ascii
    $s20 = ";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"WIj\";})(),(function f0" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}