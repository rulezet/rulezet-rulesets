rule _20160921_99369f59b90fb2df18b8570f0403febc_20160921_b18e047e5b3f_5580 {
  meta:
    description = "datamaliciousorder - from files 20160921_99369f59b90fb2df18b8570f0403febc.js, 20160921_b18e047e5b3fa2131425e272781d97b4.js, 20160921_c86a534fb694b7c269b48a9dc32f8a87.js, 20160921_d6e5226f779c21f4fc4b67aeddca2869.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "224e0a3dfee910c8afb81d7298f89c0b6e937cbd8062c03cedbe500c3dfe98a2"
    hash2       = "033421645eb5cdfdccc02e470b5304f91fa62121d1e117f1aebca723440cec70"
    hash3       = "921432f56757fdaa414b8b2f729fdd46e41c954a0a96b706c646c1d5ab09e5cb"
    hash4       = "42ec93947d9a157ccd37a3c75c7a06b75fa756fee925b759536deb0993f07a5b"

  strings:
    $s1 = "on f000(){return \"PTs\";})(),(function f000(){return \"EZu\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii
    $s2 = "MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"DNa\";})(),(functi" ascii
    $s3 = "unction f000(){return \"Vu\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Nx\";})(),(function f000(){retur" ascii
    $s4 = "MJq\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qa\";})(),(functi" ascii
    $s5 = "(function f000(){return \"Qa\";})(),(function f000(){return \"Wb\";})(),(function f000(){return \"GGn\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}