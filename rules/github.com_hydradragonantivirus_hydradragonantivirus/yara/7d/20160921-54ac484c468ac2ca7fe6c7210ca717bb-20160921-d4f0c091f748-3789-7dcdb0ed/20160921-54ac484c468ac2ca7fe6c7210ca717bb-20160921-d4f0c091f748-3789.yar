rule _20160921_54ac484c468ac2ca7fe6c7210ca717bb_20160921_d4f0c091f748_3789 {
  meta:
    description = "datamaliciousorder - from files 20160921_54ac484c468ac2ca7fe6c7210ca717bb.js, 20160921_d4f0c091f748680e400a49909c223265.js, 20160921_fe8abdad2bc00d1378e2964402e33217.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "5b883334540a4216b3582d1f2fa0a27f21b9c64a87944c8e58d9fab0f609eef3"
    hash2       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"
    hash3       = "39d0496129988da40dbbddcff6610a39be1f05ddd7f48a13058b749810c8400d"

  strings:
    $s1 = "{return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Sj\";})(" ascii
    $s2 = "ion f000(){return \"Iq\";})(),(function f000(){return \"Kw\";})(),(function f000(){return \"OUx\";})(),(function f000(){return " ascii
    $s3 = "t\";})(),(function f000(){return \"BIj\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"ZIi\";})(),(function" ascii
    $s4 = "nction f000(){return \"Sj\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"KXg\";})(),(function f000(){retur" ascii
    $s5 = "),(function f000(){return \"OUx\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"ZIi\";})(),(function f000()" ascii
    $s6 = "000(){return \"Vu\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}