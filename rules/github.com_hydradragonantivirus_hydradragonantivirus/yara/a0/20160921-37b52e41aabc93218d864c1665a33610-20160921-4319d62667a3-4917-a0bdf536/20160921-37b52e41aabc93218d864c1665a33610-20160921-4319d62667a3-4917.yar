rule _20160921_37b52e41aabc93218d864c1665a33610_20160921_4319d62667a3_4917 {
  meta:
    description = "datamaliciousorder - from files 20160921_37b52e41aabc93218d864c1665a33610.js, 20160921_4319d62667a3ba06f88c6ba9123c871b.js, 20160922_51694f0251fa3f1d7267b3d7973d4097.js, 20160922_abb8cfe456777bb23f3253a5921340d2.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "c506490b3737e1b21522717204e4143ada427e9af58fe86e42ed31dfd0fde66a"
    hash2       = "33e5babd254cb93078c026ebb6beb245e487651597122eb576cf5b870dfbf8ee"
    hash3       = "c424926fb99cca3faf3dda68a4860b770a7f0467803b01fbdf54011c52f56a99"
    hash4       = "658f6872a894eb9bcb193b7bf73260e92d4627036eede588553b81333dcf0c30"

  strings:
    $s1 = "ction f000(){return \"Vu\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"XTn\";})(),(function f000(){return" ascii
    $s2 = "function f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Vu\";})(),(function f000(){ret" ascii
    $s3 = "function f000(){return \"Vj\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"TRc\";})(),(function f000(){re" ascii
    $s4 = "WIj\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Vj\";})(),(function" ascii
    $s5 = "rn \"KXg\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qp\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}