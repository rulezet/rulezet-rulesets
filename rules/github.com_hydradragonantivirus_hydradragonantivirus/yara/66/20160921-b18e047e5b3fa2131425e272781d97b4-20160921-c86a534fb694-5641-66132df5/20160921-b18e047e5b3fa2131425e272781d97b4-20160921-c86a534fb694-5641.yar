rule _20160921_b18e047e5b3fa2131425e272781d97b4_20160921_c86a534fb694_5641 {
  meta:
    description = "datamaliciousorder - from files 20160921_b18e047e5b3fa2131425e272781d97b4.js, 20160921_c86a534fb694b7c269b48a9dc32f8a87.js, 20160921_d4f0c091f748680e400a49909c223265.js, 20160921_d6e5226f779c21f4fc4b67aeddca2869.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "033421645eb5cdfdccc02e470b5304f91fa62121d1e117f1aebca723440cec70"
    hash2       = "921432f56757fdaa414b8b2f729fdd46e41c954a0a96b706c646c1d5ab09e5cb"
    hash3       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"
    hash4       = "42ec93947d9a157ccd37a3c75c7a06b75fa756fee925b759536deb0993f07a5b"

  strings:
    $s1 = "),(function f000(){return \"OUx\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"Rh\";})(),(function f000(){" ascii
    $s2 = ")(),(function f000(){return \"Qj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Kw\";})(),(function f000()" ascii
    $s3 = "0(){return \"GGn\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"TRc" ascii
    $s4 = "\"PTi\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";})(),(func" ascii
    $s5 = "000(){return \"Um\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"GGn" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}