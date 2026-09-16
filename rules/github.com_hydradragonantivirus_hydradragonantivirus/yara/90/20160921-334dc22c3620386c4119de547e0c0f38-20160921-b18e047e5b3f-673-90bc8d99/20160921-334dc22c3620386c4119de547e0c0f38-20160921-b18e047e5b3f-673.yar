rule _20160921_334dc22c3620386c4119de547e0c0f38_20160921_b18e047e5b3f_673 {
  meta:
    description = "datamaliciousorder - from files 20160921_334dc22c3620386c4119de547e0c0f38.js, 20160921_b18e047e5b3fa2131425e272781d97b4.js, 20160921_c86a534fb694b7c269b48a9dc32f8a87.js, 20160921_d6e5226f779c21f4fc4b67aeddca2869.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a69d8e08a2b4320b4183bfad7a1baa8fc49b7361116aeb9e3a542ae416cd93d5"
    hash2       = "033421645eb5cdfdccc02e470b5304f91fa62121d1e117f1aebca723440cec70"
    hash3       = "921432f56757fdaa414b8b2f729fdd46e41c954a0a96b706c646c1d5ab09e5cb"
    hash4       = "42ec93947d9a157ccd37a3c75c7a06b75fa756fee925b759536deb0993f07a5b"

  strings:
    $s1  = "turn \"MKa\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Uo\";})(),(" ascii
    $s2  = "(),(function f000(){return \"Go\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"TRc\";})(),(function f000(" ascii
    $s3  = "on f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return " ascii
    $s4  = "ction f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){retur" ascii
    $s5  = "turn \"SEo\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"TRc\";})()" ascii
    $s6  = "Xg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s7  = "})(),(function f000(){return \"Iq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"OUx\";})(),(function f00" ascii
    $s8  = "tion f000(){return \"NBs\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"QDg\";})(),(function f000(){retur" ascii
    $s9  = "n \"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(f" ascii
    $s10 = "n \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"XTn\";})(),(f" ascii
    $s11 = "),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(function f000()" ascii
    $s12 = "n f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Iq" ascii
    $s13 = "return \"QDg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(" ascii
    $s14 = "on f000(){return \"QDg\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"" ascii
    $s15 = "rn \"IPu\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(f" ascii
    $s16 = "ction f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Go\";})(),(function f000(){return " ascii
    $s17 = "eturn \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Mc\";})()," ascii
    $s18 = "urn \"RLk\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})()," ascii
    $s19 = "rn \"Zj\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(fun" ascii
    $s20 = ";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"OMd\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}