rule TTP_XOR_QUAD_CurrentVersionRun_d0b4 {
  strings:
    $key_d0b4 = { 83 db [2] a7 d5 [2] 8c f9 [2] a2 db [2] b6 c0 [2] b9 da [2] a7 c7 [2] a5 c6 [2] be c0 [2] a2 c7 [2] be e8 }

  condition:
    any of them
}