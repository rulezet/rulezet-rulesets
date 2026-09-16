rule TTP_XOR_QUAD_CurrentVersionRun_c19c {
  strings:
    $key_c19c = { 92 f3 [2] b6 fd [2] 9d d1 [2] b3 f3 [2] a7 e8 [2] a8 f2 [2] b6 ef [2] b4 ee [2] af e8 [2] b3 ef [2] af c0 }

  condition:
    any of them
}