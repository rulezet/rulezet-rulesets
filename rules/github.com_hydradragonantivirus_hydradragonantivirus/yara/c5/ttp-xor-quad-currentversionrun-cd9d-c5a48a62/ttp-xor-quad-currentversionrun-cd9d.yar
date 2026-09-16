rule TTP_XOR_QUAD_CurrentVersionRun_cd9d {
  strings:
    $key_cd9d = { 9e f2 [2] ba fc [2] 91 d0 [2] bf f2 [2] ab e9 [2] a4 f3 [2] ba ee [2] b8 ef [2] a3 e9 [2] bf ee [2] a3 c1 }

  condition:
    any of them
}