rule _20160921_16200453422b5793a6a93d4bb423b0ea_20160921_3bce2f31e98c_4489 {
  meta:
    description = "datamaliciousorder - from files 20160921_16200453422b5793a6a93d4bb423b0ea.js, 20160921_3bce2f31e98c152d025886ed17309773.js, 20160921_c54afc417f4f2e6afc93a834c28784f2.js, 20160921_d4f0c091f748680e400a49909c223265.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "d968eb9bb2807e5889794bf130036c2c81716cd0166eed67a45c9ef3f81607c3"
    hash2       = "9a668f4a1c8cd764f3d7afa71030b8b37f7ec8d0b0b42b9a93aa82346b5ae616"
    hash3       = "20ec6b05e6f9287e0487d83e2fe14d9d0ca6d013f0a0ee7abade9f2b0b6268d5"
    hash4       = "1bfdf43dd38b68a1577a28fa30f6ebe7fbbcc8d9fe32db4ebe1b162eaac6ba98"

  strings:
    $s1 = "\"GGn\";})(),(function f000(){return \"KDh\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"WIj\";})(),(fun" ascii
    $s2 = "00(){return \"QDg\";})(),(function f000(){return \"DYs\";})(),(function f000(){return \"IAa\";})(),(function f000(){return \"Rh" ascii
    $s3 = "Gn\";})(),(function f000(){return \"Sj\";})(),(function f000(){return \"MBb\";})(),(function f000(){return \"YTp\";})(),(functio" ascii
    $s4 = "Db\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Oh\";})(),(function f000(){return \"Um\";})(),(function" ascii
    $s5 = "unction f000(){return \"ZIi\";})(),(function f000(){return \"Nx\";})(),(function f000(){return \"OMd\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}