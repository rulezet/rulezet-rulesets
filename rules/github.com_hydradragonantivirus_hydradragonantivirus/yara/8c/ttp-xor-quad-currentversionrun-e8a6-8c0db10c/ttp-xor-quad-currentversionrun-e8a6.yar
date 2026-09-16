rule TTP_XOR_QUAD_CurrentVersionRun_e8a6 {
  strings:
    $key_e8a6 = { bb c9 [2] 9f c7 [2] b4 eb [2] 9a c9 [2] 8e d2 [2] 81 c8 [2] 9f d5 [2] 9d d4 [2] 86 d2 [2] 9a d5 [2] 86 fa }

  condition:
    any of them
}