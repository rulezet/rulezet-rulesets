rule _20160921_19d073f9fafc88c8b86047e72c80e9d8_20160921_4855f7b1e1da_792 {
  meta:
    description = "datamaliciousorder - from files 20160921_19d073f9fafc88c8b86047e72c80e9d8.js, 20160921_4855f7b1e1da9c1c5863fa798f27645a.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"
    hash2       = "3c9b29105af371fead56301baf1fdec90bfe0a8b339dbda43258a67443183fcc"

  strings:
    $s1  = "\"EZu\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Tn\";})(),(funct" ascii
    $s2  = "000(){return \"UEg\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s3  = "nction f000(){return \"Vu\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){retu" ascii
    $s4  = "rn \"IAa\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(f" ascii
    $s5  = "(function f000(){return \"Qa\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Do\";})(),(function f000(){re" ascii
    $s6  = "n f000(){return \"Vj\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"" ascii
    $s7  = "rn \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(fu" ascii
    $s8  = "00(){return \"Wb\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\"" ascii
    $s9  = "urn \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Ut\";})(),(function f000(){return \"GGn\";})(),(f" ascii
    $s10 = "n f000(){return \"Qa\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"" ascii
    $s11 = "),(function f000(){return \"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"DNa\";})(),(function f000(" ascii
    $s12 = "){return \"OUx\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"YTp\";}" ascii
    $s13 = "a\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s14 = "n \"UEg\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Sj\";})(),(fun" ascii
    $s15 = "})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"ZFe\";})(),(function f00" ascii
    $s16 = "n f000(){return \"IAa\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"" ascii
    $s17 = "on f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DYs\";})(),(function f000(){return " ascii
    $s18 = "eturn \"Nv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"OMd\";})(),(function f000(){return \"GGn\";})()," ascii
    $s19 = "(){return \"Oe\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"BIj\";" ascii
    $s20 = "return \"Yv\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}