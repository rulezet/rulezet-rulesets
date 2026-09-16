rule _20160921_66566a9bbc7830091a244fa6674b709b_20160921_b18e047e5b3f_3864 {
  meta:
    description = "datamaliciousorder - from files 20160921_66566a9bbc7830091a244fa6674b709b.js, 20160921_b18e047e5b3fa2131425e272781d97b4.js, 20160921_c86a534fb694b7c269b48a9dc32f8a87.js, 20160921_d6e5226f779c21f4fc4b67aeddca2869.js, 20160921_e2594cbf75233509eaea515aa1a7a2f1.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "154f7ca38a058d2590f40ec43ada530305244e5c7e86bbedd19aa9c0e1ca02aa"
    hash2       = "033421645eb5cdfdccc02e470b5304f91fa62121d1e117f1aebca723440cec70"
    hash3       = "921432f56757fdaa414b8b2f729fdd46e41c954a0a96b706c646c1d5ab09e5cb"
    hash4       = "42ec93947d9a157ccd37a3c75c7a06b75fa756fee925b759536deb0993f07a5b"
    hash5       = "9bcadd89dbaf0700ab19bcb2d52d99cb9fdc4145fae40ae3eb529de8d9ada04c"

  strings:
    $s1 = "0(){return \"ZIi\";})(),(function f000(){return \"BMj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"GGn\"" ascii
    $s2 = "(function f000(){return \"WIj\";})(),(function f000(){return \"QDg\";})(),(function f000(){return \"Oh\";})(),(function f000(){r" ascii
    $s3 = "Ii\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(functio" ascii
    $s4 = "unction f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Yv\";})(),(function f000(){ret" ascii
    $s5 = "n \"Lp\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"Zj\";})(),(func" ascii
    $s6 = " f000(){return \"Vu\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"Sq\";})(),(function f000(){return \"TKl" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}