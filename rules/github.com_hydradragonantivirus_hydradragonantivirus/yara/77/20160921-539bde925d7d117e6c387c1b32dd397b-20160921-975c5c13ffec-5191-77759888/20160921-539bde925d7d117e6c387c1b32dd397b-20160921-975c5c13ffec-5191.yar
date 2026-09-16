rule _20160921_539bde925d7d117e6c387c1b32dd397b_20160921_975c5c13ffec_5191 {
  meta:
    description = "datamaliciousorder - from files 20160921_539bde925d7d117e6c387c1b32dd397b.js, 20160921_975c5c13ffec0e2608898a142a2baed7.js, 20160921_a56de0614f7815cff3fcb9f56233dbb4.js, 20160921_f0a3d5a403f0d7386ada786b887a464d.js, 20160921_f1cc02f488792b7161849f8d15549315.js, 20160921_fa11dbc1cb358c8446ac1ba033c8a4c7.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "9ff498e6534ca553e55771f7eceb4682e639590da978950f1c8683f05f448427"
    hash2       = "4635f6ab0f307c878451c2e13b93f8c364364fd9dbd9b0a493d7990bc3eb3c17"
    hash3       = "fa71b33b4ef1bf0fefff91c2876915e8ca80c82d473862703c383c6da0ad0186"
    hash4       = "77a7ef76313303139cf36ae2953c6c901152f97fe8ddc013a16c1d4b69e5357c"
    hash5       = "a4438fd9b6e1eb385945338a0e8eaf272adfda2172cb3659bc36af2d1cc76ce5"
    hash6       = "27a60061641d8c44f2b882fcd06e72ca5721eaecb40ea10ad0b87c0c5f3c236f"

  strings:
    $s1 = "\";})(),(function f000(){return \"Tn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"DIa\";})(),(function f" ascii
    $s2 = " \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(fun" ascii
    $s3 = "e\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Ot\";})(),(function" ascii
    $s4 = "ction f000(){return \"TRc\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Um\";})(),(function f000(){retur" ascii
    $s5 = "{return \"Ot\";})(),(function f000(){return \"Ot\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Lo\";})()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}