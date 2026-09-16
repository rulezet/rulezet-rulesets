rule _20160921_6ed03f6116d83dcb603f8d7a421669a9_20160921_7a3c07ee9b5a_355 {
  meta:
    description = "datamaliciousorder - from files 20160921_6ed03f6116d83dcb603f8d7a421669a9.js, 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js, 20160921_95270bbacde4afcb3c799d7a0643809d.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7f10930e3c0bd956023b78dabf743464a690cb292b06d107d010614acff421c1"
    hash2       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"
    hash3       = "6cab57b5e35c3714b482592a77f0edbdc9fedb8c6e508d57b8cf63dfd719f5db"

  strings:
    $s1  = "\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Lo\";})(),(function f" ascii
    $s2  = "{return \"IAa\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})" ascii
    $s3  = "eturn \"DAp\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})()," ascii
    $s4  = "turn \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Qz\";})()," ascii
    $s5  = "0(){return \"Sv\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"GGn\"" ascii
    $s6  = "ion f000(){return \"Br\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return " ascii
    $s7  = "f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Oh" ascii
    $s8  = " f000(){return \"Iq\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"UE" ascii
    $s9  = " f000(){return \"Oh\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"W" ascii
    $s10 = "unction f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Ml\";})(),(function f000(){retu" ascii
    $s11 = "\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f0" ascii
    $s12 = "rn \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Mt\";})(),(fu" ascii
    $s13 = "),(function f000(){return \"Br\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function f000()" ascii
    $s14 = "\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(function" ascii
    $s15 = "eturn \"Oh\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"GGn\";})()" ascii
    $s16 = " f000(){return \"DAp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"M" ascii
    $s17 = "unction f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Wb\";})(),(function f000(){retu" ascii
    $s18 = "0(){return \"Br\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Br\";}" ascii
    $s19 = "\"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"NBs\";})(),(func" ascii
    $s20 = "})(),(function f000(){return \"SGs\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}