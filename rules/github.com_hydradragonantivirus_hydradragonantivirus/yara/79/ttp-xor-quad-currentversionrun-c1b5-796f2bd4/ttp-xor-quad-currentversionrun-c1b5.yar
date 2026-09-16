rule TTP_XOR_QUAD_CurrentVersionRun_c1b5 {
  strings:
    $key_c1b5 = { 92 da [2] b6 d4 [2] 9d f8 [2] b3 da [2] a7 c1 [2] a8 db [2] b6 c6 [2] b4 c7 [2] af c1 [2] b3 c6 [2] af e9 }

  condition:
    any of them
}