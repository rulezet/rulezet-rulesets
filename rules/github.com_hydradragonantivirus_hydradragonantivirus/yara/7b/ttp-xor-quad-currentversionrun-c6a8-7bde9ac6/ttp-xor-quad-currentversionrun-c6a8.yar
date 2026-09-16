rule TTP_XOR_QUAD_CurrentVersionRun_c6a8 {
  strings:
    $key_c6a8 = { 95 c7 [2] b1 c9 [2] 9a e5 [2] b4 c7 [2] a0 dc [2] af c6 [2] b1 db [2] b3 da [2] a8 dc [2] b4 db [2] a8 f4 }

  condition:
    any of them
}