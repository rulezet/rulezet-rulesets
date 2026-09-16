rule _20160921_08977f7f9e06ddd41f6d4c2067611fb8_20160921_178144255388_765 {
  meta:
    description = "datamaliciousorder - from files 20160921_08977f7f9e06ddd41f6d4c2067611fb8.js, 20160921_178144255388cfaf75832e7c43b7a37d.js, 20160921_18b49c641afca0fcc3f886dc01b2641e.js, 20160921_523b4f49bbdc4dd92accd0e402a46bfd.js, 20160921_731724a743a10eb03d2ee3a92239f369.js, 20160921_a2977e58d35241f07c3f294ca2097899.js, 20160921_a7532ebefde89d14f64381982f45f5dc.js, 20160921_d4f0c091f748680e400a49909c223265.js, 20160921_d69f5159aadd1440760083d8952604c6.js, 20160921_d860185d3d51e8a363b423c048150940.js, 20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac.js, 20160921_f7b964e1d5b6c5c4999da8838c5d62ca.js, 20160921_f850d4c4897a9bd959014c9fc7d18a6b.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bfc954e02f30b2a7d9d67f82866d129c9944d4c1b1a2d6e89bf77f6d6c9f997"
    hash2       = "ceb222ab2a29064bfa74287cfdb14daf49b9474ead74db04adbe122341895903"
    hash3       = "a697115d075c4bd09fb1f58699de7b47c8cbea42964865bfac236a14f40a03c5"
    hash4       = "6f9f8d6d5ec4629c30430c47234803f947380ed84d76b2caa48ab30caee473c3"
    hash5       = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"
    hash6       = "e73f1b219b8d754435de05b984a60d0a49eb426ffb33ef307d21a1f8ee6a7880"
    hash7       = "601a014082c8ae8d379ef7ccf41dbd1f7df2b8e196161905ccc52c5565bf2b04"
    hash8       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"
    hash9       = "6a93de0a10bfc4b55037c85e12bc3eb9699d5353c4a13a206b5e16e7303d5c86"
    hash10      = "419be2ea8bb0db95703d86253063108b2da68cb9ec72abf96d06bdf5162cc75f"
    hash11      = "2db3499efc418559f17a0414ed3156ee8f0a83f7ca0cb04fe1e2d403c9f22306"
    hash12      = "a4c4c13a87b8183a01386c2463dc595a8b36ca94eff8c78305da426f160e6427"
    hash13      = "d8fc3e7e41c34088a452b3b6538d4581b58ba00503833e565b195ce374f63b54"

  strings:
    $s1  = "000(){return \"Wy\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"MJq\";})(),(function f000(){return \"DAp" ascii
    $s2  = "nction f000(){return \"Tb\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Nx\";})(),(function f000(){retur" ascii
    $s3  = "ction f000(){return \"Br\";})(),(function f000(){return \"MOc\";})(),(function f000(){return \"ZFe\";})(),(function f000(){retur" ascii
    $s4  = "Fs\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"KIc\";})(),(function f000(){return \"MBb\";})(),(functi" ascii
    $s5  = "on f000(){return \"Br\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"G" ascii
    $s6  = "on f000(){return \"TKp\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s7  = "n \"Go\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"GGn\";})(),(fun" ascii
    $s8  = "),(function f000(){return \"NBs\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Br\";})(),(function f000(){" ascii
    $s9  = "\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"Vj\";})(),(function f000(){return \"Iq\";})(),(function f" ascii
    $s10 = "(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Um\";})" ascii
    $s11 = "turn \"TKp\";})(),(function f000(){return \"YTp\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})()" ascii
    $s12 = "\"GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"BQb\";})(),(function f000(){return \"BQb\";})(),(func" ascii
    $s13 = "unction f000(){return \"MBb\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Um\";})(),(function f000(){ret" ascii
    $s14 = "unction f000(){return \"Tb\";})(),(function f000(){return \"Vu\";})(),(function f000(){return \"SGs\";})(),(function f000(){retu" ascii
    $s15 = "rn \"Fs\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"UEg\";})(),(fu" ascii
    $s16 = " f000(){return \"Br\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"U" ascii
    $s17 = "})(),(function f000(){return \"Br\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f00" ascii
    $s18 = "eturn \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"RLk\";})(),(function f000(){return \"SGs\";})(" ascii
    $s19 = "GGn\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"PTi\";})(),(function f000(){return \"DAp\";})(),(functi" ascii
    $s20 = "function f000(){return \"DYx\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"Wy\";})(),(function f000(){re" ascii

  condition:
    (uint16(0) == 0x2f0a and (8 of them)
    ) or (all of them)
}