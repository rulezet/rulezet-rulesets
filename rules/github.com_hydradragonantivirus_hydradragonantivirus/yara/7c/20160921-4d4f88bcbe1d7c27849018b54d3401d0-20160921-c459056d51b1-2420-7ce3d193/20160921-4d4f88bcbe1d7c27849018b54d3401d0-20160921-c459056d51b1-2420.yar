rule _20160921_4d4f88bcbe1d7c27849018b54d3401d0_20160921_c459056d51b1_2420 {
  meta:
    description = "datamaliciousorder - from files 20160921_4d4f88bcbe1d7c27849018b54d3401d0.js, 20160921_c459056d51b1a4ea3176139800021b35.js"
    author      = "HydraDragonAntivirus"
    reference   = "https://github.com/HydraDragonAntivirus"
    date        = "2026-04-26"
    hash1       = "8c037da0756f2e03c3daf2ada4f7a359fd0381e67b8eccb57785222e669ac983"
    hash2       = "2caf9c958877250774bdc190d1120c23a5fe115635a6c2d285aa8d62d171db39"

  strings:
    $s1 = "(){return \"Yi\";})(),(function f000(){return \"OUx\";})(),(function f000(){return \"Qz\";})(),(function f000(){return \"ZFe\";}" ascii
    $s2 = "nction f000(){return \"DNa\";})(),(function f000(){return \"UEg\";})(),(function f000(){return \"GGn\";})(),(function f000(){ret" ascii
    $s3 = "(),(function f000(){return \"Br\";})(),(function f000(){return \"Ml\";})(),(function f000(){return \"Rh\";})(),(function f000(){" ascii
    $s4 = "(){return \"Go\";})(),(function f000(){return \"Um\";})(),(function f000(){return \"Qj\";})(),(function f000(){return \"Yi\";})(" ascii
    $s5 = "Ij\";})(),(function f000(){return \"GGn\";})(),(function f000(){return \"Go\";})(),(function f000(){return \"PTs\";})(),(functio" ascii
    $s6 = "nction f000(){return \"Ml\";})(),(function f000(){return \"Wy\";})(),(function f000(){return \"DYx\";})(),(function f000(){retur" ascii
    $s7 = "\";})(),(function f000(){return \"DYx\";})(),(function f000(){return \"ZIi\";})(),(function f000(){return \"Oe\";})(),(function " ascii
    $s8 = " f000(){return \"TKl\";})(),(function f000(){return \"Qa\";})(),(function f000(){return \"Br\";})(),(function f000(){return \"DI" ascii

  condition:
    (uint16(0) == 0x2f0a and (all of them)
    ) or (all of them)
}