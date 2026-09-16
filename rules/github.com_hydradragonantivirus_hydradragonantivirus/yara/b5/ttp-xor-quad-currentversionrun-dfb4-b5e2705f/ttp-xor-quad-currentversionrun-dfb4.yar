rule TTP_XOR_QUAD_CurrentVersionRun_dfb4 {
  strings:
    $key_dfb4 = { 8c db [2] a8 d5 [2] 83 f9 [2] ad db [2] b9 c0 [2] b6 da [2] a8 c7 [2] aa c6 [2] b1 c0 [2] ad c7 [2] b1 e8 }

  condition:
    any of them
}