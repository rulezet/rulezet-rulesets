rule TTP_XOR_QUAD_CurrentVersionRun_e8b4 {
  strings:
    $key_e8b4 = { bb db [2] 9f d5 [2] b4 f9 [2] 9a db [2] 8e c0 [2] 81 da [2] 9f c7 [2] 9d c6 [2] 86 c0 [2] 9a c7 [2] 86 e8 }

  condition:
    any of them
}