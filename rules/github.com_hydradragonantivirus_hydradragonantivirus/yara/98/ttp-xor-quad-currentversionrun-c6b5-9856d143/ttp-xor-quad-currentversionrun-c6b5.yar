rule TTP_XOR_QUAD_CurrentVersionRun_c6b5 {
  strings:
    $key_c6b5 = { 95 da [2] b1 d4 [2] 9a f8 [2] b4 da [2] a0 c1 [2] af db [2] b1 c6 [2] b3 c7 [2] a8 c1 [2] b4 c6 [2] a8 e9 }

  condition:
    any of them
}