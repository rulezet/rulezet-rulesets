rule _20160921_69015d5cf863b10983b8aa49b42d835e_20160921_c54afc417f4f_128 {
  meta:
    description = "datamaliciousorder - from files 20160921_69015d5cf863b10983b8aa49b42d835e.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "797bada2609e8fc67a8ede267e9fcce2fc817f630e6fe62c7953cc722eea6d2c"
    hash2       = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"

  strings:
    $s1  = "),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTs\";})(),(function f000()" ascii
    $s2  = "return \"Mu\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Qj\";})(),(" ascii
    $s3  = "x\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f" ascii
    $s4  = " f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"S" ascii
    $s5  = "),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"KDh\";})(),(function f000(" ascii
    $s6  = "ction f000(){return \"Mu\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"OMd\";})(),(function f000(){return" ascii
    $s7  = "(){return \"OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Do\";})" ascii
    $s8  = "unction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){ret" ascii
    $s9  = "\"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"XTn\";})(),(func" ascii
    $s10 = "unction f000(){return \"OUx\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"Nv\";})(),(function f000(){retu" ascii
    $s11 = "Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(functio" ascii
    $s12 = "eturn \"XTn\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})()" ascii
    $s13 = "000(){return \"Vu\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s14 = "rn \"Iq\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"NYh\";})(),(fu" ascii
    $s15 = "n \"WIj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Do\";})(),(fun" ascii
    $s16 = "\"WIj\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(functi" ascii
    $s17 = "unction f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})(),(function f000(){retu" ascii
    $s18 = "\"TRc\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Wb\";})(),(funct" ascii
    $s19 = "on f000(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"XTn\";})(),(function f000(){return " ascii
    $s20 = "){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}