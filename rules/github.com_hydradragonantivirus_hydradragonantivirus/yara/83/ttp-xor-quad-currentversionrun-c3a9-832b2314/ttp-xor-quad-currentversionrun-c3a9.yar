rule TTP_XOR_QUAD_CurrentVersionRun_c3a9 {
  strings:
    $key_c3a9 = { 90 c6 [2] b4 c8 [2] 9f e4 [2] b1 c6 [2] a5 dd [2] aa c7 [2] b4 da [2] b6 db [2] ad dd [2] b1 da [2] ad f5 }

  condition:
    any of them
}