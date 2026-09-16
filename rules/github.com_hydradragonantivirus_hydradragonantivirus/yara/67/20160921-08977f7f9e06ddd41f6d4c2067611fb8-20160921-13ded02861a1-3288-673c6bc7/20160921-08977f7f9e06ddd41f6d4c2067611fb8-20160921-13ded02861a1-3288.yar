rule _20160921_08977f7f9e06ddd41f6d4c2067611fb8_20160921_13ded02861a1_3288 {
  meta:
    description = "datamaliciousorder - from files 20160921_08977f7f9e06ddd41f6d4c2067611fb8.js, 20160921_13ded02861a1e8b64e01061b37c5b3db.js, 20160921_178144255388cfaf75832e7c43b7a37d.js, 20160921_18b49c641afca0fcc3f886dc01b2641e.js, 20160921_1b283f7ae003e1b13aa49a95b3a9568c.js, 20160921_23ef471e720525eb3dff80c2296d1a60.js, 20160921_35e8549205da39aa60fea8ac643ade8b.js, 20160921_4855f7b1e1da9c1c5863fa798f27645a.js, 20160921_523b4f49bbdc4dd92accd0e402a46bfd.js, 20160921_5f5611940db748f8f47ad6671e45ac27.js, 20160921_61ffae07802bf5013fbbf8f137c827c3.js, 20160921_70a7f7f0df4f39e2b207e20a063c9feb.js, 20160921_731724a743a10eb03d2ee3a92239f369.js, 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js, 20160921_a2977e58d35241f07c3f294ca2097899.js, 20160921_a7532ebefde89d14f64381982f45f5dc.js, 20160921_c745108b7e58564d28687f6e180c98c5.js, 20160921_d4f0c091f748680e400a49909c223265.js, 20160921_d69f5159aadd1440760083d8952604c6.js, 20160921_d860185d3d51e8a363b423c048150940.js, 20160921_e30a7fc515c8c3fe0dd9b1892df8c5ac.js, 20160921_eb80446b9ceac6d26c554a90fd2a297d.js, 20160921_f7b964e1d5b6c5c4999da8838c5d62ca.js, 20160921_f850d4c4897a9bd959014c9fc7d18a6b.js, 20160922_e3f5fbc84de17ad7f507fc3f34b8151f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "7bfc954e02f30b2a7d9d67f82866d129c9944d4c1b1a2d6e89bf77f6d6c9f997"
    hash2       = "42e98219bdeb7e238d75b203593219e729c68b82ade5cdcb35dd8982bca8e7b8"
    hash3       = "ceb222ab2a29064bfa74287cfdb14daf49b9474ead74db04adbe122341895903"
    hash4       = "a697115d075c4bd09fb1f58699de7b47c8cbea42964865bfac236a14f40a03c5"
    hash5       = "a9b43cd6462f0f7b7e48c84642e70cda1bfb372344d51b33be67bcc3e2e2a374"
    hash6       = "b0945c221a3a5ff2958847eac00c479ff3a9b1c8dd949684148aca0eeaf3afeb"
    hash7       = "fe7319f5e948bc89c8a5f42f117ed0667b1816e94f61d88225df2d217cf74b06"
    hash8       = "3c9b29105af371fead56301baf1fdec90bfe0a8b339dbda43258a67443183fcc"
    hash9       = "6f9f8d6d5ec4629c30430c47234803f947380ed84d76b2caa48ab30caee473c3"
    hash10      = "141377c1ea41b7c63633225cdfe610934ccb5630d4fc24157bd25932c56d02e2"
    hash11      = "d1b5dbd3605683fd0b3b1dc802f1048401a8db23070c8205273f5c5ab6c5133c"
    hash12      = "a31a1dde0b2d683e4ae7fa3037209a425605b8e0a49f1607ea1dd02a4eaed267"
    hash13      = "a7ac1561634dc1fa8b18cc98ccf432021ed2e8b16132f60e88757d855dedeb94"
    hash14      = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"
    hash15      = "e73f1b219b8d754435de05b984a60d0a49eb426ffb33ef307d21a1f8ee6a7880"
    hash16      = "601a014082c8ae8d379ef7ccf41dbd1f7df2b8e196161905ccc52c5565bf2b04"
    hash17      = "933f7e4ee0e09bde34704852e63df99ed6341ecadbe6b7afc2244b8228048418"
    hash18      = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"
    hash19      = "6a93de0a10bfc4b55037c85e12bc3eb9699d5353c4a13a206b5e16e7303d5c86"
    hash20      = "419be2ea8bb0db95703d86253063108b2da68cb9ec72abf96d06bdf5162cc75f"
    hash21      = "2db3499efc418559f17a0414ed3156ee8f0a83f7ca0cb04fe1e2d403c9f22306"
    hash22      = "f41eada506c8e467101fe9817aebed4e4beb8a4e1f7e89b61d06852001c116cc"
    hash23      = "a4c4c13a87b8183a01386c2463dc595a8b36ca94eff8c78305da426f160e6427"
    hash24      = "d8fc3e7e41c34088a452b3b6538d4581b58ba00503833e565b195ce374f63b54"
    hash25      = "f0d0a0daceb43d9d9a2f5d51fcc03568ed541f8699acb8b17ce2131c29f14abf"

  strings:
    $s1 = "\"Br\";})(),(function f000(){return \"Oe\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"Br\";})(),(functio" ascii
    $s2 = "00(){return \"GGn\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Lp" ascii
    $s3 = ")(),(function f000(){return \"MBb\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"Qz\";})(),(function f000" ascii
    $s4 = "unction f000(){return \"Uo\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"BQb\";})(),(function f000(){retu" ascii
    $s5 = "nction f000(){return \"Tn\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Vj\";})(),(function f000(){retur" ascii
    $s6 = "ion f000(){return \"Wy\";})(),(function f000(){return \"Km\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}