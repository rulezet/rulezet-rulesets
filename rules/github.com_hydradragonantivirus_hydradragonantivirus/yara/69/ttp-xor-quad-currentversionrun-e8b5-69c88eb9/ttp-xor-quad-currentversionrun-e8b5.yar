rule TTP_XOR_QUAD_CurrentVersionRun_e8b5 {
  strings:
    $key_e8b5 = { bb da [2] 9f d4 [2] b4 f8 [2] 9a da [2] 8e c1 [2] 81 db [2] 9f c6 [2] 9d c7 [2] 86 c1 [2] 9a c6 [2] 86 e9 }

  condition:
    any of them
}