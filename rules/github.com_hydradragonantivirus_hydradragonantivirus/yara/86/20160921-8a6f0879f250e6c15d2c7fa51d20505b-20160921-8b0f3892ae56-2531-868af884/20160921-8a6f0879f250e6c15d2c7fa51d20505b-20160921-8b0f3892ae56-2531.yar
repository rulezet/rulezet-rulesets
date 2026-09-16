rule _20160921_8a6f0879f250e6c15d2c7fa51d20505b_20160921_8b0f3892ae56_2531 {
  meta:
    description = "datamaliciousorder - from files 20160921_8a6f0879f250e6c15d2c7fa51d20505b.js, 20160921_8b0f3892ae56f8c06d3baa62c262a12f.js, 20160921_8dac417cb4331fdefcd724e5c4563731.js, 20160921_c6163df7a6dda28826544197fc8ddc4f.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "221e50c91cd5c3d541d89b6c9999d61bacb186433ba85ae94088851587c25391"
    hash2       = "96514db18a22f5e5bde10feb1f6b426e5772d0f7e76f227e8d49a7a00bfb01b7"
    hash3       = "4ab6c9959d63ff05f6b1074253866e4ba4ca6148b9d820313ac79da48c63d90e"
    hash4       = "c0d0b12b3c6fc559a577159775ce104e897b9b5c0422b945c7c097dd53710fe8"

  strings:
    $s1 = "function f000(){return \"DNa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){r" ascii
    $s2 = "\"WIj\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"PTs\";})(),(func" ascii
    $s3 = "00(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZFe\"" ascii
    $s4 = "on f000(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"" ascii
    $s5 = "00(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";}" ascii
    $s6 = "Na\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(functio" ascii
    $s7 = "function f000(){return \"Ml\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"DYx\";})(),(function f000(){ret" ascii
    $s8 = "})(),(function f000(){return \"Br\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Rh\";})(),(function f000(" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}