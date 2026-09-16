rule _20160921_19d073f9fafc88c8b86047e72c80e9d8_20160921_e1bc53e337e2_993 {
  meta:
    description = "datamaliciousorder - from files 20160921_19d073f9fafc88c8b86047e72c80e9d8.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9b03e3cbdce0a3374d427a6b76ef3eb59bc90337947054be78218aab4aa3a5f9"
    hash2       = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"

  strings:
    $s1  = "00(){return \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\"" ascii
    $s2  = "0(){return \"OMd\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Wy\";" ascii
    $s3  = ")(),(function f000(){return \"Lo\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZGq\";})(),(function f000" ascii
    $s4  = "),(function f000(){return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(" ascii
    $s5  = "tion f000(){return \"QDg\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"DIa\";})(),(function f000(){return" ascii
    $s6  = "Do\";})(),(function f000(){return \"DIa\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s7  = "Mz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"ZFe\";})(),(functio" ascii
    $s8  = "n \"QDg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Qj\";})(),(func" ascii
    $s9  = "n \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"OMd\";})(),(fun" ascii
    $s10 = ";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Tn\";})(),(function f0" ascii
    $s11 = "rn \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yv\";})(),(f" ascii
    $s12 = "rn \"NBs\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Yv\";})(),(f" ascii
    $s13 = "tion f000(){return \"PTs\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return" ascii
    $s14 = "){return \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"PTs\";})" ascii
    $s15 = "n f000(){return \"MKa\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return " ascii
    $s16 = "ction f000(){return \"Yv\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s17 = "(),(function f000(){return \"OUx\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Oe\";})(),(function f000()" ascii
    $s18 = "f000(){return \"Vj\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg" ascii
    $s19 = "h\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(functio" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}