rule TTP_XOR_QUAD_CurrentVersionRun_c49c {
  strings:
    $key_c49c = { 97 f3 [2] b3 fd [2] 98 d1 [2] b6 f3 [2] a2 e8 [2] ad f2 [2] b3 ef [2] b1 ee [2] aa e8 [2] b6 ef [2] aa c0 }

  condition:
    any of them
}