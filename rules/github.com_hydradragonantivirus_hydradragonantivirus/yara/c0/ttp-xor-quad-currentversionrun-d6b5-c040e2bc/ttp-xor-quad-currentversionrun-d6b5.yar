rule TTP_XOR_QUAD_CurrentVersionRun_d6b5 {
  strings:
    $key_d6b5 = { 85 da [2] a1 d4 [2] 8a f8 [2] a4 da [2] b0 c1 [2] bf db [2] a1 c6 [2] a3 c7 [2] b8 c1 [2] a4 c6 [2] b8 e9 }

  condition:
    any of them
}