rule TTP_XOR_QUAD_CurrentVersionRun_c69c {
  strings:
    $key_c69c = { 95 f3 [2] b1 fd [2] 9a d1 [2] b4 f3 [2] a0 e8 [2] af f2 [2] b1 ef [2] b3 ee [2] a8 e8 [2] b4 ef [2] a8 c0 }

  condition:
    any of them
}