rule _20160921_1ccc6f9d608f6057f34a9f01f0cf5abe_20160921_3e524aa8d0a1_4617 {
  meta:
    description = "datamaliciousorder - from files 20160921_1ccc6f9d608f6057f34a9f01f0cf5abe.js, 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js, 20160921_e949fdc198fee477717395093f5853e7.js, 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "226d26c073abdcaab4155bb0b8d789289cf0a453f58c9f6383385cc78660a27e"
    hash2       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"
    hash3       = "4ff56149c45e72e300c579a750f7d49b8e0e723f75bb7a74343267578dd71a4d"
    hash4       = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"

  strings:
    $s1 = "\"Yi\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";})(),(functi" ascii
    $s2 = "turn \"TKl\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Do\";})(),(function f000(){return \"KXg\";})()," ascii
    $s3 = "00(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"TKl" ascii
    $s4 = "ion f000(){return \"OUx\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii
    $s5 = "ion f000(){return \"TKl\";})(),(function f000(){return \"XTn\";})(),(function f000(){return \"Yi\";})(),(function f000(){return " ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}