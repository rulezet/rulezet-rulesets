rule _20160921_1766f5c818d6371cb36488c98158ccd2_20160921_1f7d568f432a_4504 {
  meta:
    description = "datamaliciousorder - from files 20160921_1766f5c818d6371cb36488c98158ccd2.js, 20160921_1f7d568f432abb102bc2d5dbd6c68c22.js, 20160921_202394e6610dfa0f27f737c781d5c579.js, 20160921_24cca85b9483630d2e2e50bdd8aa5013.js, 20160921_3d472332b6f7d53a9f60478e1312ea58.js, 20160921_66de660457cd1dcbe458e50b91bafaca.js, 20160921_8d22ed47876b303a1415a88483556238.js, 20160921_99369f59b90fb2df18b8570f0403febc.js, 20160921_a4213841acc34547cdaa9cab58f8e2d8.js, 20160921_a864250b4ae6162ed0d7a2f3ed785d46.js, 20160921_c05dd34a09358454c56b9c248f1d0304.js, 20160921_ccabe4fce99c1ebb627aa374a501f33c.js, 20160921_cebdb99ce2e54d24acef5b8ee0096562.js, 20160921_ded524cdc972424d0fa8254648795d71.js, 20160921_e1bc53e337e27af13c4323bd3332a33c.js, 20160921_e6569e3fc498e9fab243cf8dcef2ac51.js, 20160921_f1b8df0ab75abc0c2b3be738559f2ab3.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "4d8985b767534ef1312401b6a38570477e0c87ed4ef37c945eee55179929c0a4"
    hash2       = "193a02aff0ca7f757ef6d01358baac9c7338cd556144a08982dce9382eff6344"
    hash3       = "d10df61dcb3a781b5266597c0f1a9d52066cebbebf5196ad93fd81855575ed11"
    hash4       = "59d00368c1188c6d6bc66f675b72e99608dc018c3528d523610abc2745ea88cd"
    hash5       = "afa09723c03c97cb533583268f8fb586a7ccfc3438d793acc59eedb90be55b5b"
    hash6       = "0c92eafe23596e161cf04cc6206b7e5cac5dafb3ce36772cc5a8a4f0f827211c"
    hash7       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"
    hash8       = "224e0a3dfee910c8afb81d7298f89c0b6e937cbd8062c03cedbe500c3dfe98a2"
    hash9       = "3bdfe74e5399936e0bca26e7caeb97bfdab7631164f7ae885438865cb52fa076"
    hash10      = "f64f9f9fd1a5e4b096281bd9733f52c453683cc9032801264dd73f202b17964f"
    hash11      = "e330ec83e6ac964ffd679e6589494a6108e1995f570c539dee7b1be30953f8a3"
    hash12      = "449fe576ee25f77acba5442d771e770819941d7dbf354b5123ca5211ef743189"
    hash13      = "87071d18d308dc7717dabe03dc0d11efe7ee7231e95d9fca71e480f5f2430f7d"
    hash14      = "09c4ea683259322d1696083646a9b96190b4796e8b3fdf91ba2bf4f6296afaa9"
    hash15      = "7561e1bb060dd07ca80dc6e0b089a853d0081d60c7843d73299f7dabb92efaea"
    hash16      = "d08c501a52afbdcde7669d2b9c40865025e38aa75b2aebf8c71433565dbc7010"
    hash17      = "dfdf24fc382cd60cf8d9c01ff0bca33ee060801ad2bd963895209ac610525301"

  strings:
    $s1 = "eturn \"DYx\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"KIc\";})()," ascii
    $s2 = "(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"Fs\";})(),(function f000(){return \"MBb\";}" ascii
    $s3 = "})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"DYx\";})(),(function f0" ascii
    $s4 = "n f000(){return \"KIc\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"" ascii
    $s5 = "n \"Yi\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(fu" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}