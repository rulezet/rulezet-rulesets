rule _20160921_3a185c9392a67b927e245520858a0afc_20160921_5d475fd55c4e_4966 {
  meta:
    description = "datamaliciousorder - from files 20160921_3a185c9392a67b927e245520858a0afc.js, 20160921_5d475fd55c4e461509ccd87876cf56f7.js, 20160921_68596411289b2d10a74a19f9fce4a325.js, 20160921_814eb57aeffc75442964829345cc9f96.js, 20160921_89a260f4d6da4d97f251f843cf5e94b0.js, 20160921_b18e047e5b3fa2131425e272781d97b4.js, 20160921_c86a534fb694b7c269b48a9dc32f8a87.js, 20160921_d4a195112732d8d5ebb1bdc900a52d50.js, 20160921_d53637406b068b7f313912a4769e371e.js, 20160921_d6e5226f779c21f4fc4b67aeddca2869.js, 20160922_2bdee31da941689170d6b7da303eeff6.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a5201f237db515e70a3934feb4ff64c4cccf728f340d6e9e46fbe4217f988165"
    hash2       = "dc4e4001f0f2e1f28098f6ad190b918a7ffe075d590fb142a508fdad546d9816"
    hash3       = "52b104c52d9f1461833687ee9fc5da1913610266114cbc0018bf345ee135d662"
    hash4       = "2736df4d651a33824aba7abffa7c08414414ffed9f5f27b4b2d81101cfeb7117"
    hash5       = "700f6c802eb024896efe2b22255973b53752a8f129213c9bba2c4f2ebdc53988"
    hash6       = "033421645eb5cdfdccc02e470b5304f91fa62121d1e117f1aebca723440cec70"
    hash7       = "921432f56757fdaa414b8b2f729fdd46e41c954a0a96b706c646c1d5ab09e5cb"
    hash8       = "679537ccc73765d47769657cc000499c86fa227678df5b0d4690ca0e2cf6325c"
    hash9       = "cafcf490b9e4364e16ee46f82e53896038b46a0b37f3fd7a33a363316965b400"
    hash10      = "42ec93947d9a157ccd37a3c75c7a06b75fa756fee925b759536deb0993f07a5b"
    hash11      = "70ee088e40fb9f7bd2cc1514b94af7f28ef9fd68444cdbd3859858840ae0e498"

  strings:
    $s1 = "(),(function f000(){return \"Yz\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000()" ascii
    $s2 = "0(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"UOt\";})(),(function f000(){return \"GGn\"" ascii
    $s3 = "n \"UEg\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Wy\";})(),(func" ascii
    $s4 = "\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"GGn\";})(),(function " ascii
    $s5 = "ion f000(){return \"TKl\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Tn\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}