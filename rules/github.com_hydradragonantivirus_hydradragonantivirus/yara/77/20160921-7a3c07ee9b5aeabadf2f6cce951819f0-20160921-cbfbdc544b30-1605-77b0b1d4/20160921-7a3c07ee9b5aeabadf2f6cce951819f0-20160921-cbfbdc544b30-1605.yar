rule _20160921_7a3c07ee9b5aeabadf2f6cce951819f0_20160921_cbfbdc544b30_1605 {
  meta:
    description = "datamaliciousorder - from files 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js, 20160921_cbfbdc544b309301bc71d300d7726545.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"
    hash2       = "135f44db2fcd47db2f5b9cd01f10f5c892ae119d904f5cb0ea4bbdaafba92963"

  strings:
    $s1  = "return \"Tn\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Mu\";})(),(function f000(){return \"Qa\";})()," ascii
    $s2  = "a\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s3  = "return \"BMj\";})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"UEg\";})(" ascii
    $s4  = "ction f000(){return \"HJm\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(function f000(){return" ascii
    $s5  = "n \"RLk\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"IAa\";})(),(fu" ascii
    $s6  = "n f000(){return \"TRc\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(function f000(){return \"" ascii
    $s7  = ")(),(function f000(){return \"Nv\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Tn\";})(),(function f000()" ascii
    $s8  = "0(){return \"GGn\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Zj\";" ascii
    $s9  = "000(){return \"Rh\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\"" ascii
    $s10 = "),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"IAa\";})(),(function f000()" ascii
    $s11 = "tion f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return" ascii
    $s12 = "rn \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Nv\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}