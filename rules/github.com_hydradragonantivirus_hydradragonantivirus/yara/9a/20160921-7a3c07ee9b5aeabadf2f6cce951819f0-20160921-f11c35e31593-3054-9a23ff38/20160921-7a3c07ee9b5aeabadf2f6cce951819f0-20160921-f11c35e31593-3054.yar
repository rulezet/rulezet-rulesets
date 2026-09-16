rule _20160921_7a3c07ee9b5aeabadf2f6cce951819f0_20160921_f11c35e31593_3054 {
  meta:
    description = "datamaliciousorder - from files 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js, 20160921_f11c35e3159325debfd0a307299c4087.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"
    hash2       = "f18be6e3d6cc83db6a4204656661ec0e213eded871d58d50b9d2c8b212b94cbd"

  strings:
    $s1 = "0(){return \"XTn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"ZFe" ascii
    $s2 = " \"Oe\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"BIj\";})(),(fun" ascii
    $s3 = "\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function" ascii
    $s4 = "function f000(){return \"MJq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii
    $s5 = "0(){return \"Lp\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Go\";" ascii
    $s6 = "{return \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"PTs\";})" ascii
    $s7 = "nction f000(){return \"PTs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Do\";})(),(function f000(){retur" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}