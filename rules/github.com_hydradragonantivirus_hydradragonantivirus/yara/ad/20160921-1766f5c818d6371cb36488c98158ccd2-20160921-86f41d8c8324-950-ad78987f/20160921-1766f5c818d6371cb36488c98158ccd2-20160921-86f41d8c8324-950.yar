rule _20160921_1766f5c818d6371cb36488c98158ccd2_20160921_86f41d8c8324_950 {
  meta:
    description = "datamaliciousorder - from files 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_86f41d8c83240a68770674107f15f162.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash2       = "56a4c0b8742284d9e8907df1b8d73d9c73ee82bc9595e88d869c555afd77312d"

  strings:
    $s1  = ";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"ZGq\";})(),(function f" ascii
    $s2  = "\"Oe\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s3  = "n f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"HJm\";})(),(function f000(){return " ascii
    $s4  = "eturn \"DYs\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})()," ascii
    $s5  = ",(function f000(){return \"RLk\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"TKp\";})(),(function f000(){" ascii
    $s6  = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTi\";})(),(f" ascii
    $s7  = "u\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(function" ascii
    $s8  = "0(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Qz\"" ascii
    $s9  = "0(){return \"RVb\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\"" ascii
    $s10 = "})(),(function f000(){return \"PTi\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"QDg\";})(),(function f0" ascii
    $s11 = "(){return \"Ml\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Vj\";})" ascii
    $s12 = "rn \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(fu" ascii
    $s13 = "000(){return \"DYs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn" ascii
    $s14 = "turn \"Go\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s15 = "(),(function f000(){return \"Tn\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000()" ascii
    $s16 = "tion f000(){return \"DYx\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Oe\";})(),(function f000(){return" ascii
    $s17 = "return \"Wy\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})()" ascii
    $s18 = ",(function f000(){return \"Km\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Yv\";})(),(function f000(){r" ascii
    $s19 = "Aa\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Lp\";})(),(function" ascii
    $s20 = "\"Sv\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"DIa\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}