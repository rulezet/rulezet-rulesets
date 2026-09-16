rule _20160921_02b826231ece268e91633311d2c70554_20160921_2746dcb02909_942 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_46b3ab412369507850a916abad1e6bf0.js, 20160921_4c22609fd7310d7f415ca007620a244b.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js, 20160921_6ed03f6116d83dcb603f8d7a421669a9.js, 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js, 20160921_95270bbacde4afcb3c799d7a0643809d.js, 20160921_c9a772728edf4eeff48c1aea32c00a13.js, 20160921_d6eab67b6b3cec2e5f5426840b084b70.js, 20160921_dff46b67b973e99ec02248f10c2f55c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash3       = "ff7968bb25038246a127bf97a5d4f0afb2c088f5ccd47c093b21d1aa27116fdd"
    hash4       = "2c98aee98a3263e75913535b49eb469916a931e86a23075b07289143bf0fa3f8"
    hash5       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"
    hash6       = "7f10930e3c0bd956023b78dabf743464a690cb292b06d107d010614acff421c1"
    hash7       = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"
    hash8       = "6cab57b5e35c3714b482592a77f0edbdc9fedb8c6e508d57b8cf63dfd719f5db"
    hash9       = "76f52cefe2f1cf5954919532ecd1ec4c5c9072cb4edc435169d570baa9894ed9"
    hash10      = "0ae44892f78e5b5ddfc07e6a23fb55469f21e12c45e74661ad81e61b07893ece"
    hash11      = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"

  strings:
    $s1  = "(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Tn\";})(),(function f000(){re" ascii
    $s2  = "ion f000(){return \"SEo\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return" ascii
    $s3  = "0(){return \"Br\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Br\";}" ascii
    $s4  = "ction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){retur" ascii
    $s5  = " \"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DAp\";})(),(fun" ascii
    $s6  = "{return \"UEg\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})" ascii
    $s7  = "(){return \"MJq\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";" ascii
    $s8  = "})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f000" ascii
    $s9  = "ction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Yi\";})(),(function f000(){return" ascii
    $s10 = "n\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"PTs\";})(),(function" ascii
    $s11 = "tion f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"OMd\";})(),(function f000(){return" ascii
    $s12 = "rn \"Br\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(fun" ascii
    $s13 = " f000(){return \"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"" ascii
    $s14 = "0(){return \"YTp\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj" ascii
    $s15 = "})(),(function f000(){return \"Br\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Wy\";})(),(function f000(" ascii
    $s16 = "return \"GGn\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"NYh\";})(" ascii
    $s17 = "\"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Oh\";})(),(funct" ascii
    $s18 = "GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Qj\";})(),(functio" ascii
    $s19 = "){return \"TKp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";}" ascii
    $s20 = ",(function f000(){return \"RVb\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}