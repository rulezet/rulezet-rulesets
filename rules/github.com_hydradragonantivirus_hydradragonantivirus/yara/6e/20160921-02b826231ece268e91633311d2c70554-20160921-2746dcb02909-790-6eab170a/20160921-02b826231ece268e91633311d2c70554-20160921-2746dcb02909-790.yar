rule _20160921_02b826231ece268e91633311d2c70554_20160921_2746dcb02909_790 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_46b3ab412369507850a916abad1e6bf0.js, 20160921_4c22609fd7310d7f415ca007620a244b.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js, 20160921_6ed03f6116d83dcb603f8d7a421669a9.js, 20160921_6f40563df6afd13be332d60057d492bb.js, 20160921_71668d4dffd1de11d5c597a2f98e2266.js, 20160921_72cf8bebbcf48b45894fe7d7b3327a58.js, 20160921_7a3c07ee9b5aeabadf2f6cce951819f0.js, 20160921_83a4b9dfccb435ab7121b53e70b2bb23.js, 20160921_95270bbacde4afcb3c799d7a0643809d.js, 20160921_99d82d33214407e421e255b85f02daae.js, 20160921_be882ab89423f06a9e76ba0cb72775fe.js, 20160921_c9a772728edf4eeff48c1aea32c00a13.js, 20160921_d47b4a8df4397da0f8d93fe0d9eeb14b.js, 20160921_d6eab67b6b3cec2e5f5426840b084b70.js, 20160921_dc989bc33de845eef9826b241e933829.js, 20160921_dff46b67b973e99ec02248f10c2f55c2.js, 20160921_e08237183b6bb8840bdab8df29dc62ff.js, 20160922_99c635a67f8963210ce99c7a8cf9cd6c.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash3       = "ff7968bb25038246a127bf97a5d4f0afb2c088f5ccd47c093b21d1aa27116fdd"
    hash4       = "2c98aee98a3263e75913535b49eb469916a931e86a23075b07289143bf0fa3f8"
    hash5       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"
    hash6       = "7f10930e3c0bd956023b78dabf743464a690cb292b06d107d010614acff421c1"
    hash7       = "f6d3d773ad865f7e3793e6540facc0b8f68d4f503990e93cebc41b933a338a40"
    hash8       = "d9bf036d8b4743496b663218b8ff488676bee9250e9706c1179536db46cbba61"
    hash9       = "004799df77a97e1e1816f6a4a1acf9bec5dfd13ae07613832796a6c9ef0cc578"
    hash10      = "f3f9ad4055c2ff243fcdf662544ac5eff6ef170765938a028b9c6e0029fcb2a7"
    hash11      = "ad277513de073e1dfeba70577234c4da10406e1298f5253b5cf48893971016ed"
    hash12      = "6cab57b5e35c3714b482592a77f0edbdc9fedb8c6e508d57b8cf63dfd719f5db"
    hash13      = "9f95318ee468d352a07628edd848ed3cb97379fab3e416b20eeb631ea656c3a9"
    hash14      = "fe4f2a5579ff9cbd713377a0d5f78bb0c6c30247b6f455ccdb4014a7c298c978"
    hash15      = "76f52cefe2f1cf5954919532ecd1ec4c5c9072cb4edc435169d570baa9894ed9"
    hash16      = "78db1c7c22d3adc33c9ba580ac46df953d36c9c15f9c8b211dc68c16595dc18d"
    hash17      = "0ae44892f78e5b5ddfc07e6a23fb55469f21e12c45e74661ad81e61b07893ece"
    hash18      = "780c5e07d33732406de5b51436310fbaacb6d3c6fdcb8d9fa40733ae6e903508"
    hash19      = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"
    hash20      = "8d131000a0c435e8674de7020c3a970768f0d66e5b0cf5f711017057a318c00f"
    hash21      = "c5b5cdc3be24f457939814321b7f3397a8f4d2370b1e57cdae1f3f10537e562c"

  strings:
    $s1  = " \"Br\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(funct" ascii
    $s2  = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"EZu\";})(),(function f000(){retu" ascii
    $s3  = "on f000(){return \"BMj\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"" ascii
    $s4  = "00(){return \"Vu\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\"" ascii
    $s5  = "000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"Qa" ascii
    $s6  = " \"Uo\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s7  = "ion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return " ascii
    $s8  = "unction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){retu" ascii
    $s9  = "0(){return \"YTp\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\"" ascii
    $s10 = "Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(functio" ascii
    $s11 = "turn \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"Mt\";})()," ascii
    $s12 = "000(){return \"DNa\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn" ascii
    $s13 = "0(){return \"MBb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\"" ascii
    $s14 = "{return \"EZu\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"KXg\";})" ascii
    $s15 = "nction f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"DAp\";})(),(function f000(){retu" ascii
    $s16 = "unction f000(){return \"IPu\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){retu" ascii
    $s17 = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"Go\";})(),(func" ascii
    $s18 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"RVb\";})(),(function f00" ascii
    $s19 = "o\";})(),(function f000(){return \"Nv\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Do\";})(),(function " ascii
    $s20 = "\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"IPu\";})(),(function " ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}