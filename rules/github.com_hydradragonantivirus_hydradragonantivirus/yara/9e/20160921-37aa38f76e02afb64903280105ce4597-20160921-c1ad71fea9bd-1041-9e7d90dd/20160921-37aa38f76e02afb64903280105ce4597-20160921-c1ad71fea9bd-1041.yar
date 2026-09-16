rule _20160921_37aa38f76e02afb64903280105ce4597_20160921_c1ad71fea9bd_1041 {
  meta:
    description = "datamaliciousorder - from files 20160921_37aa38f76e02afb64903280105ce4597.js, 20160921_c1ad71fea9bd3e371590c0c373f087a1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "768a32c669c193375bb8e7adb97cdbb697cd6f4f09fb5dc67bb63e62b7de29cf"
    hash2       = "cf0e0decfb5414f48e1bcf494a6c63e6249e9ac1433d4fba6a461b5970957194"

  strings:
    $s1  = "ion f000(){return \"Qa\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"" ascii
    $s2  = "ion f000(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s3  = "turn \"EZu\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"MDb\";})()" ascii
    $s4  = "urn \"PTs\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"Wb\";})(),(" ascii
    $s5  = " f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DY" ascii
    $s6  = ",(function f000(){return \"Sj\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"Vj\";})(),(function f000(){re" ascii
    $s7  = "n f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"" ascii
    $s8  = "nction f000(){return \"UEg\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Wb\";})(),(function f000(){retu" ascii
    $s9  = "0(){return \"Sq\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";" ascii
    $s10 = ")(),(function f000(){return \"TKp\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"GGn\";})(),(function f000" ascii
    $s11 = "on f000(){return \"Um\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"" ascii
    $s12 = ";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"MDb\";})(),(function f00" ascii
    $s13 = "f000(){return \"Qa\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Yi\"" ascii
    $s14 = "urn \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Um\";})(),(f" ascii
    $s15 = "nction f000(){return \"Sv\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"MDb\";})(),(function f000(){retur" ascii
    $s16 = "n f000(){return \"Qa\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Rh\";})(),(function f000(){return \"Yi" ascii
    $s17 = "000(){return \"GGn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"SEo" ascii
    $s18 = "),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Nv\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}