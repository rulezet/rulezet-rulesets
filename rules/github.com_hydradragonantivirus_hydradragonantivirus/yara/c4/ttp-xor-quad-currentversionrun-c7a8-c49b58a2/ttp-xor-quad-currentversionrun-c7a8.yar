rule TTP_XOR_QUAD_CurrentVersionRun_c7a8 {
  strings:
    $key_c7a8 = { 94 c7 [2] b0 c9 [2] 9b e5 [2] b5 c7 [2] a1 dc [2] ae c6 [2] b0 db [2] b2 da [2] a9 dc [2] b5 db [2] a9 f4 }

  condition:
    any of them
}