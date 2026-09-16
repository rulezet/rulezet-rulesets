rule _20160921_8c33029db61426a234eddfae1623641b_20160921_93e612a2f44e_910 {
  meta:
    description = "datamaliciousorder - from files 20160921_8c33029db61426a234eddfae1623641b.js, 20160921_93e612a2f44e1198dfe3c296cb4f7b79.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8a7c2a5271a5dc64c200145fa7252ff19d736174b3556eb436f9ac8941daec71"
    hash2       = "e88aa94cf06df033312260c4a58f453654133758e66e1d2df4f11f9de9bfec7c"

  strings:
    $s1  = "QDg\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"SGs\";})(),(functio" ascii
    $s2  = " \"Kw\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s3  = ",(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Wh\";})(),(function f000(){" ascii
    $s4  = ",(function f000(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(){r" ascii
    $s5  = "nction f000(){return \"QDg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Sj\";})(),(function f000(){retur" ascii
    $s6  = "ion f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s7  = " \"Yv\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s8  = "(){return \"GGn\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vu\";" ascii
    $s9  = "{return \"Vj\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Do\";})()" ascii
    $s10 = "000(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"GGn" ascii
    $s11 = "(){return \"Vj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";}" ascii
    $s12 = "){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Yi\";})" ascii
    $s13 = " f000(){return \"Wy\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"DY" ascii
    $s14 = "(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"Iq\";}" ascii
    $s15 = ",(function f000(){return \"Nx\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Tn\";})(),(function f000(){re" ascii
    $s16 = "MMz\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(funct" ascii
    $s17 = "(function f000(){return \"Km\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Uo\";})(),(function f000(){re" ascii
    $s18 = "00(){return \"OUx\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"ZFe\"" ascii
    $s19 = "turn \"KXg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Zj\";})(),(" ascii
    $s20 = "})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"ZFe\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}