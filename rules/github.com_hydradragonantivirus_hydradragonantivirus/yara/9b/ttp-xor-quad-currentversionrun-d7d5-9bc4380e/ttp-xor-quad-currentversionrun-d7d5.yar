rule TTP_XOR_QUAD_CurrentVersionRun_d7d5 {
  strings:
    $key_d7d5 = { 84 ba [2] a0 b4 [2] 8b 98 [2] a5 ba [2] b1 a1 [2] be bb [2] a0 a6 [2] a2 a7 [2] b9 a1 [2] a5 a6 [2] b9 89 }

  condition:
    any of them
}