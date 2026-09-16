rule TTP_XOR_QUAD_CurrentVersionRun_dfb5 {
  strings:
    $key_dfb5 = { 8c da [2] a8 d4 [2] 83 f8 [2] ad da [2] b9 c1 [2] b6 db [2] a8 c6 [2] aa c7 [2] b1 c1 [2] ad c6 [2] b1 e9 }

  condition:
    any of them
}