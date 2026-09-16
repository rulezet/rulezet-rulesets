rule TTP_XOR_QUAD_CurrentVersionRun_cd9c {
  strings:
    $key_cd9c = { 9e f3 [2] ba fd [2] 91 d1 [2] bf f3 [2] ab e8 [2] a4 f2 [2] ba ef [2] b8 ee [2] a3 e8 [2] bf ef [2] a3 c0 }

  condition:
    any of them
}