rule TTP_XOR_QUAD_CurrentVersionRun_cd97 {
  strings:
    $key_cd97 = { 9e f8 [2] ba f6 [2] 91 da [2] bf f8 [2] ab e3 [2] a4 f9 [2] ba e4 [2] b8 e5 [2] a3 e3 [2] bf e4 [2] a3 cb }

  condition:
    any of them
}