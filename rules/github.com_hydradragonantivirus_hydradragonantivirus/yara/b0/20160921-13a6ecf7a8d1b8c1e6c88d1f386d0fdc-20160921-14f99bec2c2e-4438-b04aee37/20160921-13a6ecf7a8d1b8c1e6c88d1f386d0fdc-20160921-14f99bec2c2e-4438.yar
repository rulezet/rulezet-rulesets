rule _20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc_20160921_14f99bec2c2e_4438 {
  meta:
    description = "datamaliciousorder - from files 20160921_13a6ecf7a8d1b8c1e6c88d1f386d0fdc.js, 20160921_14f99bec2c2ed0c000bf0acbf6c2260c.js, 20160921_3e524aa8d0a18c87370a789c7bba4fc5.js, 20160921_85f6e34eb7e2f53408ead6aab6d7f923.js, 20160921_b5e2b5a2e8f104e719b3c6631c08f1f7.js, 20160921_e59567324a545ca23bf9e3ba990b6526.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "a1db38abaeb5bf0ea6f5b5ff0f4a9eedd9ce90cd62e2966ce8936e8e8fbc2905"
    hash2       = "224106b166fc0a998ec1d58e5d4a78c585bdeb76194d93210753d7d0f558c06b"
    hash3       = "71a83b86275cb43222066a6d27dfb98cdd9fc8283b2b007f9262c38686262b9a"
    hash4       = "5005d4ac4c04b94b5c8e15a81b5b50ecf9189f0e4afa203ae5195bec5a82b02f"
    hash5       = "8495e7e7fc77026b5e5681ac973eefb0561cb5cce78632996de59641ce00258e"
    hash6       = "ce1d8f63fc8c7b91e97f36fa89b000d70fc284d08682ca3a91ee6c2a4e6e2c72"

  strings:
    $s1 = "(){return \"Zj\";})(),(function f000(){return \"KZr\";})(),(function f000(){return \"Zj\";})(),(function f000(){return \"MMz\";}" ascii
    $s2 = ",(function f000(){return \"SGs\";})(),(function f000(){return \"Iq\";})(),(function f000(){return \"Wy\";})(),(function f000(){r" ascii
    $s3 = "on f000(){return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"T" ascii
    $s4 = "return \"TKp\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"SEo\";})(),(function f000(){return \"NBs\";})" ascii
    $s5 = "a\";})(),(function f000(){return \"MMz\";})(),(function f000(){return \"MKa\";})(),(function f000(){return \"Uo\";})(),(function" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}