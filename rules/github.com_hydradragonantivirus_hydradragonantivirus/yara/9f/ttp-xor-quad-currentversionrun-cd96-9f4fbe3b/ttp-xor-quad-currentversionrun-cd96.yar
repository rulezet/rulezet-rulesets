rule TTP_XOR_QUAD_CurrentVersionRun_cd96 {
  strings:
    $key_cd96 = { 9e f9 [2] ba f7 [2] 91 db [2] bf f9 [2] ab e2 [2] a4 f8 [2] ba e5 [2] b8 e4 [2] a3 e2 [2] bf e5 [2] a3 ca }

  condition:
    any of them
}