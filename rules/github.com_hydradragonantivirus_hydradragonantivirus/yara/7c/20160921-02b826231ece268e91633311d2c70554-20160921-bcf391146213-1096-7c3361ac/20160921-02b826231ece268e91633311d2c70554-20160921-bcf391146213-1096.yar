rule _20160921_02b826231ece268e91633311d2c70554_20160921_bcf391146213_1096 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_bcf3911462135150c96c6b8eccf51628.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "b552c80ce6e203066590d8d065eb3336f999e3f3336ff06bb686520de3f326c5"

  strings:
    $s1  = "\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function " ascii
    $s2  = "g\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s3  = "000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Sq" ascii
    $s4  = "urn \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"OUx\";})(),(" ascii
    $s5  = "000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Qz" ascii
    $s6  = "(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"OUx\";}" ascii
    $s7  = "00(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"PTs\"" ascii
    $s8  = "unction f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DIa\";})(),(function f000(){ret" ascii
    $s9  = "n \"PTi\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"OMd\";})(),(fu" ascii
    $s10 = "on f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"I" ascii
    $s11 = "ion f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s12 = "(){return \"Ot\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";}" ascii
    $s13 = " \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"ZFe\";})(),(fun" ascii
    $s14 = "n f000(){return \"IAa\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"" ascii
    $s15 = "ion f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"" ascii
    $s16 = "(),(function f000(){return \"Sv\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Iq\";})(),(function f000(){" ascii
    $s17 = "n \"KXg\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(fun" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}