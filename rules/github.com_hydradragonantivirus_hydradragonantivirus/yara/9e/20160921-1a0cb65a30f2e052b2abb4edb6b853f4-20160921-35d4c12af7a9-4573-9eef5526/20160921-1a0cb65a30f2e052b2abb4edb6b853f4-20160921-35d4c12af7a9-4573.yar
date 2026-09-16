rule _20160921_1a0cb65a30f2e052b2abb4edb6b853f4_20160921_35d4c12af7a9_4573 {
  meta:
    description = "datamaliciousorder - from files 20160921_1a0cb65a30f2e052b2abb4edb6b853f4.js, 20160921_35d4c12af7a9481959a41a055c396673.js, 20160921_3a888f864f15e69e777cbaaa06f962e5.js, 20160921_74a9afe189b59f0b8148a7f92f42b125.js, 20160921_7caba45960de8ab0904dc3a8514f2614.js, 20160921_a8c002f684df9aec957f2a082ed80d84.js, 20160921_d97203a3a0e9b5b38b8653b55adf994e.js, 20160921_e2617d9e437c12b61ada4700f8e426b8.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "cb576c42df90a554f241d4a5ba0dee1dfcb9caf661cf46a2800b743aa592e644"
    hash2       = "1c2412951fad30bb8b34aca279acd07c03a437936261b0d90334331b98cf1e99"
    hash3       = "65826487c59973db0339cbaf1f8e99201516dc26d5bdf1991855fafe9cbc5da1"
    hash4       = "5ce6bfd72ee0a8f8259b2cfbaa6f5b49ec72ab64b03caf4bd2a4f733ef96925b"
    hash5       = "f07b11e4aaeb00f3fa8863261ca37d382057c7775579fae2a5744dcfdb99cd95"
    hash6       = "9db5f5694048d441a47fe4382700213cc288d4fba152eec7b99fdd310a50ef7d"
    hash7       = "4500fdca6df5cc18d7f5e360c950817a72f82196c8ae55d8bcdf74d96a8bba21"
    hash8       = "732b58fdcabccece6ef3ce710e7c0ba505cd66ea292afad6fac2c48739151b46"

  strings:
    $s1 = "ction fuck(){return \"Fv\";})(),(function fuck(){return \"XHj\";})(),(function fuck(){return \"Fv\";})(),(function fuck(){return" ascii
    $s2 = "(function fuck(){return \"KVh\";})(),(function fuck(){return \"ZWu\";})(),(function fuck(){return \"UXf\";})(),(function fuck(){" ascii
    $s3 = "(){return \"UXf\";})(),(function fuck(){return \"Sx\";})(),(function fuck(){return \"Xg\";})(),(function fuck(){return \"UXf\";}" ascii
    $s4 = "fuck(){return \"Na\";})(),(function fuck(){return \"IOs\";})(),(function fuck(){return \"Ik\";})(),(function fuck(){return \"UXf" ascii
    $s5 = " \"ZVi\";})(),(function fuck(){return \"Dc\";})(),(function fuck(){return \"Za\";})(),(function fuck(){return \"Mw\";})(),(funct" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}