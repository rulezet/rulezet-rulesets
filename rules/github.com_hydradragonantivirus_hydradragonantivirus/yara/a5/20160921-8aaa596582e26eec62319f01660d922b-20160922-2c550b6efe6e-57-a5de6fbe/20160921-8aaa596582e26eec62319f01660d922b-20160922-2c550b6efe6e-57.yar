rule _20160921_8aaa596582e26eec62319f01660d922b_20160922_2c550b6efe6e_57 {
  meta:
    description = "datamaliciousorder - from files 20160921_8aaa596582e26eec62319f01660d922b.js, 20160922_2c550b6efe6ec163893e1c555d256b4e.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "345c67f8d573844507dfad7f05cf340f1a2bb19331e3e0d242c508445594aac6"
    hash2       = "deabc297df80ed9899178f4a02c9538b2fe3ee2038528e07da89655f0d68b1a1"

  strings:
    $s1  = "00(){return \"RPt\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn" ascii
    $s2  = "\"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s3  = " \"QDg\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TKl\";})(),(fun" ascii
    $s4  = "tion f000(){return \"WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return" ascii
    $s5  = "){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"ZGq\";" ascii
    $s6  = "Xg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function" ascii
    $s7  = "tion f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s8  = "turn \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj\";})(),(" ascii
    $s9  = "nction f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"KXg\";})(),(function f000(){retu" ascii
    $s10 = "j\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Ml\";})(),(function " ascii
    $s11 = "g\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(functio" ascii
    $s12 = "return \"PTi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(" ascii
    $s13 = "tion f000(){return \"RPt\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZGq\";})(),(function f000(){retur" ascii
    $s14 = " \"OUx\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"ZGq\";})(),(fun" ascii
    $s15 = "000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Zj" ascii
    $s16 = "rn \"Qj\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl\";})(),(f" ascii
    $s17 = "Vj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"OMd\";})(),(function" ascii
    $s18 = "nction f000(){return \"MDb\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"MMz\";})(),(function f000(){ret" ascii
    $s19 = " \"TKl\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s20 = "eturn \"Zj\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Sq\";})(),(" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}