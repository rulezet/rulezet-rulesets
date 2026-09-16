rule _20160921_08977f7f9e06ddd41f6d4c2067611fb8_20160921_13ded02861a1_487 {
  meta:
    description = "datamaliciousorder - from files 20160921_08977f7f9e06ddd41f6d4c2067611fb8.js, 20160921_13ded02861a1e8b64e01061b37c5b3db.js, 20160921_178144255388cfaf75832e7c43b7a37d.js, 20160921_18b49c641afca0fcc3f886dc01b2641e.js, 20160921_23ef471e720525eb3dff80c2296d1a60.js, 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js, 20160921_523b4f49bbdc4dd92accd0e402a46bfd.js, 20160921_56d2e5a83b597694b265cf7813cc5cf0.js, 20160921_61ffae07802bf5013fbbf8f137c827c3.js, 20160921_6d9213179dbb863530a638df47003a46.js, 20160921_731724a743a10eb03d2ee3a92239f369.js, 20160921_9c9fcc818a7064d7449eec45fbad08d9.js, 20160921_a2977e58d35241f07c3f294ca2097899.js, 20160921_a7532ebefde89d14f64381982f45f5dc.js, 20160921_d4f0c091f748680e400a49909c223265.js, 20160921_d69f5159aadd1440760083d8952604c6.js, 20160921_d860185d3d51e8a363b423c048150940.js, 20160921_e0e06f5c94b0cde962f3e4c452e69af8.js, 20160921_e2594cbf75233509eaea515aa1a7a2f1.js, 20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac.js, 20160921_ebd0ee36b6a55e4cbf431d8fa9a2aea3.js, 20160921_f7b964e1d5b6c5c4999da8838c5d62ca.js, 20160921_f850d4c4897a9bd959014c9fc7d18a6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bfc954e02f30b2a7d9d67f82866d129c9944d4c1b1a2d6e89bf77f6d6c9f997"
    hash2       = "42e98219bdeb7e238d75b203593219e729c68b82ade5cdcb35dd8982bca8e7b8"
    hash3       = "ceb222ab2a29064bfa74287cfdb14daf49b9474ead74db04adbe122341895903"
    hash4       = "a697115d075c4bd09fb1f58699de7b47c8cbea42964865bfac236a14f40a03c5"
    hash5       = "b0945c221a3a5ff2958847eac00c479ff3a9b1c8dd949684148aca0eeaf3afeb"
    hash6       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"
    hash7       = "6f9f8d6d5ec4629c30430c47234803f947380ed84d76b2caa48ab30caee473c3"
    hash8       = "b300925c1fcfafa296560c761acd7f9f31acb743cbc98bed4f8a0053b68560eb"
    hash9       = "d1b5dbd3605683fd0b3b1dc802f1048401a8db23070c8205273f5c5ab6c5133c"
    hash10      = "34dd6eef77156ff6a8475b4f23b98a3d4a6110228a40cb85c7d0c36dd8cb71c1"
    hash11      = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"
    hash12      = "988df854145081fce0af79178c78ce75ca8d89b6666ec2e052b7f8de43bb1101"
    hash13      = "e73f1b219b8d754435de05b984a60d0a49eb426ffb33ef307d21a1f8ee6a7880"
    hash14      = "601a014082c8ae8d379ef7ccf41dbd1f7df2b8e196161905ccc52c5565bf2b04"
    hash15      = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"
    hash16      = "6a93de0a10bfc4b55037c85e12bc3eb9699d5353c4a13a206b5e16e7303d5c86"
    hash17      = "419be2ea8bb0db95703d86253063108b2da68cb9ec72abf96d06bdf5162cc75f"
    hash18      = "c9140c7affc44d690abfb95dc146d3e298e2cfddacedfee85549119f368d56d1"
    hash19      = "9bcadd89dbaf0700ab19bcb2d52d99cb9fdc4145fae40ae3eb529de8d9ada04c"
    hash20      = "2db3499efc418559f17a0414ed3156ee8f0a83f7ca0cb04fe1e2d403c9f22306"
    hash21      = "f2f666db493211ee6edb824e429f601fccdbf25cd3cc08bc16ad31fdf23c4636"
    hash22      = "a4c4c13a87b8183a01386c2463dc595a8b36ca94eff8c78305da426f160e6427"
    hash23      = "d8fc3e7e41c34088a452b3b6538d4581b58ba00503833e565b195ce374f63b54"

  strings:
    $s1  = "tion f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"PTi\";})(),(function f000(){return" ascii
    $s2  = "\"SGs\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"WIj\";})(),(func" ascii
    $s3  = "n f000(){return \"DAp\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"" ascii
    $s4  = "n f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"" ascii
    $s5  = "tion f000(){return \"Qa\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"BMj\";})(),(function f000(){return" ascii
    $s6  = "00(){return \"Iq\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";" ascii
    $s7  = "turn \"Br\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Br\";})(),(f" ascii
    $s8  = "f000(){return \"YTp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn" ascii
    $s9  = " \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"IPu\";})(),(fun" ascii
    $s10 = "\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Mc\";})(),(function f" ascii
    $s11 = "f000(){return \"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Wy" ascii
    $s12 = "\"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"NBs\";})(),(func" ascii
    $s13 = "unction f000(){return \"SEo\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Qz\";})(),(function f000(){ret" ascii
    $s14 = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){retur" ascii
    $s15 = "ction f000(){return \"GGn\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"SEo\";})(),(function f000(){retur" ascii
    $s16 = ",(function f000(){return \"Nv\";})(),(function f000(){return \"Yv\";})(),(function f000(){return \"Wb\";})(),(function f000(){re" ascii
    $s17 = "n f000(){return \"KDh\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"" ascii
    $s18 = "),(function f000(){return \"DYx\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Br\";})(),(function f000()" ascii
    $s19 = " \"GGn\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"GGn\";})(),(func" ascii
    $s20 = "f000(){return \"ZIi\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"GGn" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}