rule TTP_XOR_QUAD_CurrentVersionRun_d7a8 {
  strings:
    $key_d7a8 = { 84 c7 [2] a0 c9 [2] 8b e5 [2] a5 c7 [2] b1 dc [2] be c6 [2] a0 db [2] a2 da [2] b9 dc [2] a5 db [2] b9 f4 }

  condition:
    any of them
}