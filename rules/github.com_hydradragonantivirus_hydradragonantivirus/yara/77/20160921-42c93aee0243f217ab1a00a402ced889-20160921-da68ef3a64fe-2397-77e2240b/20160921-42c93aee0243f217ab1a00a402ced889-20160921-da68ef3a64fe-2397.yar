rule _20160921_42c93aee0243f217ab1a00a402ced889_20160921_da68ef3a64fe_2397 {
  meta:
    description = "datamaliciousorder - from files 20160921_42c93aee0243f217ab1a00a402ced889.js, 20160921_da68ef3a64fe9761a5f4505bcaef8f82.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "740dfd31653bea8abfef6b3038aec0b854878d45a8de4bde67cdb9124c6bbea0"
    hash2       = "cecd93896e2d90bed54f31f9e387b5dcec7c277d5e455e561112b07c63d26ed5"

  strings:
    $s1 = "(){return \"Sv\";})(),(function f000(){return \"RVb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"MDb\";" ascii
    $s2 = "b\";})(),(function f000(){return \"DAp\";})(),(function f000(){return \"TKp\";})(),(function f000(){return \"Qa\";})(),(function" ascii
    $s3 = ",(function f000(){return \"Yv\";})(),(function f000(){return \"Yz\";})(),(function f000(){return \"Yi\";})(),(function f000(){re" ascii
    $s4 = "tion f000(){return \"Qz\";})(),(function f000(){return \"TKl\";})(),(function f000(){return \"Zj\";})(),(function f000(){return " ascii
    $s5 = "n f000(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"" ascii
    $s6 = ";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"KXg\";})(),(function f000(){return \"GGn\";})(),(function f0" ascii
    $s7 = "),(function f000(){return \"TKl\";})(),(function f000(){return \"ZFe\";})(),(function f000(){return \"Yi\";})(),(function f000()" ascii
    $s8 = "nction f000(){return \"GGn\";})(),(function f000(){return \"ZGq\";})(),(function f000(){return \"BMj\";})(),(function f000(){ret" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}