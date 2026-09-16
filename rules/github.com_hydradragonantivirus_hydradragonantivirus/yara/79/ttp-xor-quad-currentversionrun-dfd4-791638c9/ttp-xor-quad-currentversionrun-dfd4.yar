rule TTP_XOR_QUAD_CurrentVersionRun_dfd4 {
  strings:
    $key_dfd4 = { 8c bb [2] a8 b5 [2] 83 99 [2] ad bb [2] b9 a0 [2] b6 ba [2] a8 a7 [2] aa a6 [2] b1 a0 [2] ad a7 [2] b1 88 }

  condition:
    any of them
}