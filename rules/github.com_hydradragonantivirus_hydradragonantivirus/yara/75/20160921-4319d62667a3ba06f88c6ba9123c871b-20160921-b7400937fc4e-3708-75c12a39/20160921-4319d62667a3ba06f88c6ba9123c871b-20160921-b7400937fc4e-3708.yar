rule _20160921_4319d62667a3ba06f88c6ba9123c871b_20160921_b7400937fc4e_3708 {
  meta:
    description = "datamaliciousorder - from files 20160921_4319d62667a3ba06f88c6ba9123c871b.js, 20160921_b7400937fc4eb76c7ea3adaa321d7619.js, 20160922_51694f0251fa3f1d7267b3d7973d4097.js, 20160922_abb8cfe456777bb23f3253a5921340d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "33e5babd254cb93078c026ebb6beb245e487651597122eb576cf5b870dfbf8ee"
    hash2       = "91a8cd111f3381e8f00611988dc7860cfb507d4d297884f9d7d7a01ae96c0fca"
    hash3       = "c424926fb99cca3faf3dda68a4860b770a7f0467803b01fbdf54011c52f56a99"
    hash4       = "658f6872a894eb9bcb193b7bf73260e92d4627036eede588553b81333dcf0c30"

  strings:
    $s1 = "00(){return \"Sj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"TRc\";" ascii
    $s2 = "tion f000(){return \"Vu\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"RPt\";})(),(function f000(){return" ascii
    $s3 = "return \"GGn\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})" ascii
    $s4 = "00(){return \"ZGq\";})(),(function f000(){return \"HJm\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"GGn" ascii
    $s5 = " f000(){return \"KXg\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"V" ascii
    $s6 = "Ij\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Nx\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}