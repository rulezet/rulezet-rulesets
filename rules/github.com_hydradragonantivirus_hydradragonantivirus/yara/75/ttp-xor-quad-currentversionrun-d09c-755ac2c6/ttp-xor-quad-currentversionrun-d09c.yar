rule TTP_XOR_QUAD_CurrentVersionRun_d09c {
  strings:
    $key_d09c = { 83 f3 [2] a7 fd [2] 8c d1 [2] a2 f3 [2] b6 e8 [2] b9 f2 [2] a7 ef [2] a5 ee [2] be e8 [2] a2 ef [2] be c0 }

  condition:
    any of them
}