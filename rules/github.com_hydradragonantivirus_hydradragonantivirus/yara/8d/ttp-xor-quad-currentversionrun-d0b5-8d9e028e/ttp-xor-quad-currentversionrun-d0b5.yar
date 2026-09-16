rule TTP_XOR_QUAD_CurrentVersionRun_d0b5 {
  strings:
    $key_d0b5 = { 83 da [2] a7 d4 [2] 8c f8 [2] a2 da [2] b6 c1 [2] b9 db [2] a7 c6 [2] a5 c7 [2] be c1 [2] a2 c6 [2] be e9 }

  condition:
    any of them
}