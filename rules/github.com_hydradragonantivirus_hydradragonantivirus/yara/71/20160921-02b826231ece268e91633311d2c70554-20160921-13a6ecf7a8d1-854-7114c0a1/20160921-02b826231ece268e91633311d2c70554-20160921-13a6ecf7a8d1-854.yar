rule _20160921_02b826231ece268e91633311d2c70554_20160921_13a6ecf7a8d1_854 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_331df381948e6d95c6a9496aeda63d16.js, 20160921_46b3ab412369507850a916abad1e6bf0.js, 20160921_4c22609fd7310d7f415ca007620a244b.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js, 20160921_63def3fff7f150b1f60fee716b458fd6.js, 20160921_71668d4dffd1de11d5c597a2f98e2266.js, 20160921_83a4b9dfccb435ab7121b53e70b2bb23.js, 20160921_99d82d33214407e421e255b85f02daae.js, 20160921_c9a772728edf4eeff48c1aea32c00a13.js, 20160921_d47b4a8df4397da0f8d93fe0d9eeb14b.js, 20160921_d6eab67b6b3cec2e5f5426840b084b70.js, 20160921_dc989bc33de845eef9826b241e933829.js, 20160921_dff46b67b973e99ec02248f10c2f55c2.js, 20160921_ff1932b6e91481dd80ff6251296b57fe.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash3       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash4       = "74d3e5ca6efd3e26128cb4a5ab3009003c70f505b353304608d74dfd028df0d7"
    hash5       = "ff7968bb25038246a127bf97a5d4f0afb2c088f5ccd47c093b21d1aa27116fdd"
    hash6       = "2c98aee98a3263e75913535b49eb469916a931e86a23075b07289143bf0fa3f8"
    hash7       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"
    hash8       = "85e2ab59983c4c704998f4c7c577cd8211e7b590b3f200f88616fe64954c10ea"
    hash9       = "d9bf036d8b4743496b663218b8ff488676bee9250e9706c1179536db46cbba61"
    hash10      = "ad277513de073e1dfeba70577234c4da10406e1298f5253b5cf48893971016ed"
    hash11      = "9f95318ee468d352a07628edd848ed3cb97379fab3e416b20eeb631ea656c3a9"
    hash12      = "76f52cefe2f1cf5954919532ecd1ec4c5c9072cb4edc435169d570baa9894ed9"
    hash13      = "78db1c7c22d3adc33c9ba580ac46df953d36c9c15f9c8b211dc68c16595dc18d"
    hash14      = "0ae44892f78e5b5ddfc07e6a23fb55469f21e12c45e74661ad81e61b07893ece"
    hash15      = "780c5e07d33732406de5b51436310fbaacb6d3c6fdcb8d9fa40733ae6e903508"
    hash16      = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"
    hash17      = "07e5271d8517f89575dc2737fae5e8da89c7f2f25cd40c68e183d826da6b2bf0"

  strings:
    $s1  = "{return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"Sj\";})(" ascii
    $s2  = "n \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"YTp\";})(),(fu" ascii
    $s3  = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"" ascii
    $s4  = "ction f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"TKp\";})(),(function f000(){retur" ascii
    $s5  = "ction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return" ascii
    $s6  = "urn \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"Qj\";})(),(f" ascii
    $s7  = " f000(){return \"Br\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"UE" ascii
    $s8  = "Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"EZu\";})(),(functio" ascii
    $s9  = "(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"RVb\"" ascii
    $s10 = "n f000(){return \"IAa\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s11 = "\"Uo\";})(),(function f000(){return \"NYh\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s12 = "(function f000(){return \"PTs\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"GGn\";})(),(function f000(){" ascii
    $s13 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"Sv\";})(),(function f000(){return \"ZIi\";})(),(function f000" ascii
    $s14 = "(function f000(){return \"Br\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"DYx\";})(),(function f000(){re" ascii
    $s15 = "){return \"Br\";})(),(function f000(){return \"Lo\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"HJm\";})(" ascii
    $s16 = "\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"PTs\";})(),(function f000(){return \"DYx\";})(),(function " ascii
    $s17 = "turn \"Mt\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(" ascii
    $s18 = "on f000(){return \"Br\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"" ascii
    $s19 = "nction f000(){return \"Br\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Iq\";})(),(function f000(){return" ascii
    $s20 = "0(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Iq\";" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}