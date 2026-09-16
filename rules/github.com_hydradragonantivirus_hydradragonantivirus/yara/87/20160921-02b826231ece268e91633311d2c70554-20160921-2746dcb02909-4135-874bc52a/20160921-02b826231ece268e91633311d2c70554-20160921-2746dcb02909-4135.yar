rule _20160921_02b826231ece268e91633311d2c70554_20160921_2746dcb02909_4135 {
  meta:
    description = "datamaliciousorder - from files 20160921_02b826231ece268e91633311d2c70554.js, 20160921_2746dcb029094ed409681059b0bf7b68.js, 20160921_46b3ab412369507850a916abad1e6bf0.js, 20160921_4c22609fd7310d7f415ca007620a244b.js, 20160921_582a5b9e6263457a7095e1d0bf6ab96b.js, 20160921_c9a772728edf4eeff48c1aea32c00a13.js, 20160921_d6eab67b6b3cec2e5f5426840b084b70.js, 20160921_dff46b67b973e99ec02248f10c2f55c2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4131eddf30a37bcc8a29ac1639ae3a6b259a3ecfc92b73a08091b2907434cf79"
    hash2       = "9908788e148928c5f3ee88b22ad1ed33dbf69f1ffd103491ebd438b979bb77eb"
    hash3       = "ff7968bb25038246a127bf97a5d4f0afb2c088f5ccd47c093b21d1aa27116fdd"
    hash4       = "2c98aee98a3263e75913535b49eb469916a931e86a23075b07289143bf0fa3f8"
    hash5       = "ef65e5e7f2b9ad6a0714382fda8dc9fde658333c4a3ea2cdf04558bfe763c3b6"
    hash6       = "76f52cefe2f1cf5954919532ecd1ec4c5c9072cb4edc435169d570baa9894ed9"
    hash7       = "0ae44892f78e5b5ddfc07e6a23fb55469f21e12c45e74661ad81e61b07893ece"
    hash8       = "2ea0ce06677c6aad57b6618a39beaa56b2c9060cb989c2213eb782aca5d747c2"

  strings:
    $s1 = "on f000(){return \"Um\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s2 = "rn \"PTs\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\";})(),(fu" ascii
    $s3 = "{return \"PTi\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})" ascii
    $s4 = ")(),(function f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Oh\";})(),(function f000(" ascii
    $s5 = "000(){return \"Wy\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn\"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}