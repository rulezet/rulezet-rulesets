rule TTP_XOR_QUAD_CurrentVersionRun_d8b5 {
  strings:
    $key_d8b5 = { 8b da [2] af d4 [2] 84 f8 [2] aa da [2] be c1 [2] b1 db [2] af c6 [2] ad c7 [2] b6 c1 [2] aa c6 [2] b6 e9 }

  condition:
    any of them
}