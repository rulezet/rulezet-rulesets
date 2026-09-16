rule _20160922_b06824c3d57db547b98db8d6b10525d0_20160922_ddc158d1b090_96 {
  meta:
    description = "datamaliciousorder - from files 20160922_b06824c3d57db547b98db8d6b10525d0.js, 20160922_ddc158d1b0906f773c8ee4447daa25e5.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "73bcfec2ac113640d73b2ea0f0c348d7bc7d672d6be74cb4398f8669b599694b"
    hash2       = "da7f290c48869e8adc8a27e6344a762283ddaa55eae77000c5439a118d259a98"

  strings:
    $s1  = "OUx\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Lp\";})(),(functio" ascii
    $s2  = "rn \"DAp\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s3  = "0(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"MKa\";" ascii
    $s4  = " \"Nv\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"ZGq\";})(),(func" ascii
    $s5  = "000(){return \"Qj\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"ZGq" ascii
    $s6  = "n\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"NBs\";})(),(function" ascii
    $s7  = "tion f000(){return \"Qz\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return " ascii
    $s8  = "{return \"MDb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"OMd\";})" ascii
    $s9  = " f000(){return \"RPt\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"" ascii
    $s10 = "n \"Qz\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Qa\";})(),(fun" ascii
    $s11 = "rn \"Vu\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Yi\";})(),(fun" ascii
    $s12 = "00(){return \"ZGq\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj" ascii
    $s13 = "n \"GGn\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"ZGq\";})(),(fun" ascii
    $s14 = ")(),(function f000(){return \"Br\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"XTn\";})(),(function f000(" ascii
    $s15 = "{return \"RPt\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})()" ascii
    $s16 = ",(function f000(){return \"TKl\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TRc\";})(),(function f000()" ascii
    $s17 = "n f000(){return \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Z" ascii
    $s18 = "ction f000(){return \"KXg\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"TKl\";})(),(function f000(){retu" ascii
    $s19 = "})(),(function f000(){return \"Qp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f00" ascii
    $s20 = "(function f000(){return \"IAa\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"ZGq\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}