rule _20160921_08977f7f9e06ddd41f6d4c2067611fb8_20160921_9ed8ba5d12b4_358 {
  meta:
    description = "datamaliciousorder - from files 20160921_08977f7f9e06ddd41f6d4c2067611fb8.js, 20160921_9ed8ba5d12b4be06b54bbeb7c9325180.js, 20160921_a2977e58d35241f07c3f294ca2097899.js, 20160921_a65ac281dbfddbf6dbe63a0288de8c70.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bfc954e02f30b2a7d9d67f82866d129c9944d4c1b1a2d6e89bf77f6d6c9f997"
    hash2       = "19b8471b5bf67286e6bfe340e23abef1def848daa18c886f2eddc2eeaa160df7"
    hash3       = "e73f1b219b8d754435de05b984a60d0a49eb426ffb33ef307d21a1f8ee6a7880"
    hash4       = "5498e9d2bd6a9339a0b2314825151361bd8dd59a555d034973bbcac8e2cb195a"

  strings:
    $s1  = "ion f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"XTn\";})(),(function f000(){return" ascii
    $s2  = "})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f00" ascii
    $s3  = "00(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Yi" ascii
    $s4  = ")(),(function f000(){return \"KXg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sv\";})(),(function f000" ascii
    $s5  = "nction f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(function f000(){retur" ascii
    $s6  = "ction f000(){return \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){retur" ascii
    $s7  = " \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"Lp\";})(),(funct" ascii
    $s8  = "){return \"XTn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";}" ascii
    $s9  = "ion f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return " ascii
    $s10 = "j\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function " ascii
    $s11 = "tion f000(){return \"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(function f000(){return " ascii
    $s12 = " \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(fun" ascii
    $s13 = "j\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f" ascii
    $s14 = "function f000(){return \"RPt\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){ret" ascii
    $s15 = "rn \"Do\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(fun" ascii
    $s16 = ";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Kw\";})(),(function f0" ascii
    $s17 = "n \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(f" ascii
    $s18 = "0(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"RPt\"" ascii
    $s19 = " f000(){return \"WIj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"G" ascii
    $s20 = "000(){return \"Do\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"PTs" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}