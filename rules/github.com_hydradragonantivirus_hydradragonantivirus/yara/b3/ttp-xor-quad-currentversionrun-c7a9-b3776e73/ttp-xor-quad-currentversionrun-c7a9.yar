rule TTP_XOR_QUAD_CurrentVersionRun_c7a9 {
  strings:
    $key_c7a9 = { 94 c6 [2] b0 c8 [2] 9b e4 [2] b5 c6 [2] a1 dd [2] ae c7 [2] b0 da [2] b2 db [2] a9 dd [2] b5 da [2] a9 f5 }

  condition:
    any of them
}