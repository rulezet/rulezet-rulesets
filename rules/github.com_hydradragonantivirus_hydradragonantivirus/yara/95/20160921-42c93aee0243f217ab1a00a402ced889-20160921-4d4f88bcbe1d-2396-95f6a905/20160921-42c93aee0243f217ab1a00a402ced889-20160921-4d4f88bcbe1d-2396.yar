rule _20160921_42c93aee0243f217ab1a00a402ced889_20160921_4d4f88bcbe1d_2396 {
  meta:
    description = "datamaliciousorder - from files 20160921_42c93aee0243f217ab1a00a402ced889.js, 20160921_4d4f88bcbe1d7c27849018b54d3401d0.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "740dfd31653bea8abfef6b3038aec0b854878d45a8de4bde67cdb9124c6bbea0"
    hash2       = "8c037da0756f2e03c3daf2ada4f7a359fd0381e67b8eccb57785222e669ac983"

  strings:
    $s1 = "function f000(){return \"KXg\";})(),(function f000(){return \"RPt\";})(),(function f000(){return \"Qa\";})(),(function f000(){re" ascii
    $s2 = "return \"PTs\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"Zj\";})()" ascii
    $s3 = "ion f000(){return \"WIj\";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"DYx\";})(),(function f000(){return " ascii
    $s4 = "return \"GGn\";})(),(function f000(){return \"DNa\";})(),(function f000(){return \"Mc\";})(),(function f000(){return \"ZFe\";})(" ascii
    $s5 = ";})(),(function f000(){return \"Lp\";})(),(function f000(){return \"Mt\";})(),(function f000(){return \"GGn\";})(),(function f00" ascii
    $s6 = "PTs\";})(),(function f000(){return \"NBs\";})(),(function f000(){return \"Yi\";})(),(function f000(){return \"WIj\";})(),(functi" ascii
    $s7 = " f000(){return \"Do\";})(),(function f000(){return \"TRc\";})(),(function f000(){return \"WIj\";})(),(function f000(){return \"Z" ascii
    $s8 = "f000(){return \"MDb\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Uo\";})(),(function f000(){return \"Yv" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}