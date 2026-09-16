rule TTP_XOR_QUAD_CurrentVersionRun_c6a9 {
  strings:
    $key_c6a9 = { 95 c6 [2] b1 c8 [2] 9a e4 [2] b4 c6 [2] a0 dd [2] af c7 [2] b1 da [2] b3 db [2] a8 dd [2] b4 da [2] a8 f5 }

  condition:
    any of them
}