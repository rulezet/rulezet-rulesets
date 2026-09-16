rule TTP_XOR_QUAD_CurrentVersionRun_cd9a {
  strings:
    $key_cd9a = { 9e f5 [2] ba fb [2] 91 d7 [2] bf f5 [2] ab ee [2] a4 f4 [2] ba e9 [2] b8 e8 [2] a3 ee [2] bf e9 [2] a3 c6 }

  condition:
    any of them
}