rule _20160921_8b0f3892ae56f8c06d3baa62c262a12f_20160921_975c5c13ffec_5520 {
  meta:
    description = "datamaliciousorder - from files 20160921_8b0f3892ae56f8c06d3baa62c262a12f.js, 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_a56de0614f7815cff3fcb9f56233dbb4.js, 20160921_f1cc02f488792b7161849f8d15549315.js, 20160921_fa11dbc1cb358c8446ac1ba033c8a4c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "96514db18a22f5e5bde10feb1f6b426e5772d0f7e76f227e8d49a7a00bfb01b7"
    hash2       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash3       = "fa71b33b4ef1bf0fefff91c2876915e8ca80c82d473862703c383c6da0ad0186"
    hash4       = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"
    hash5       = "27a60061641d8c44f2b882fcd06e72ca5721eaecb40ea10ad0b87c0c5f3c236f"

  strings:
    $s1 = "00(){return \"WIj\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"TKl" ascii
    $s2 = "rn \"Kw\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"TRc\";})(),(fun" ascii
    $s3 = "ction f000(){return \"WIj\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qz\";})(),(function f000(){retur" ascii
    $s4 = "eturn \"Qz\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})()," ascii
    $s5 = "nction f000(){return \"Qz\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"Zj\";})(),(function f000(){return" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}