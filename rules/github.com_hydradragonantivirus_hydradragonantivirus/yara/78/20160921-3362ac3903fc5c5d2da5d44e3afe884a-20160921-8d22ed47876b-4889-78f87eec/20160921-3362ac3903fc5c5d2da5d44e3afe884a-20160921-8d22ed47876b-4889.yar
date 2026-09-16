rule _20160921_3362ac3903fc5c5d2da5d44e3afe884a_20160921_8d22ed47876b_4889 {
  meta:
    description = "datamaliciousorder - from files 20160921_3362ac3903fc5c5d2da5d44e3afe884a.js, 20160921_8d22ed47876b303a1415a88483556238.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "923e3ebc3e8bab3120c507f019cac28dec05009a69ab441bfb8be6f7f1a4d258"
    hash2       = "666a3f8cd9a533a20e260aad6bcb18265aad030f6f978c4cc3c9da557262f1ae"

  strings:
    $s1 = "ion f000(){return \"Yz\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"GGn\";})(),(function f000(){return " ascii
    $s2 = "n f000(){return \"ZGq\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"IPu\";})(),(function f000(){return \"" ascii
    $s3 = "{return \"Mc\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"IAa\";})(" ascii
    $s4 = " f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Tb\";})(),(function f000(){return \"D" ascii
    $s5 = "),(function f000(){return \"TKp\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"TRc\";})(),(function f000()" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}