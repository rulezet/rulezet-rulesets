rule TTP_XOR_QUAD_CurrentVersionRun_c1b4 {
  strings:
    $key_c1b4 = { 92 db [2] b6 d5 [2] 9d f9 [2] b3 db [2] a7 c0 [2] a8 da [2] b6 c7 [2] b4 c6 [2] af c0 [2] b3 c7 [2] af e8 }

  condition:
    any of them
}