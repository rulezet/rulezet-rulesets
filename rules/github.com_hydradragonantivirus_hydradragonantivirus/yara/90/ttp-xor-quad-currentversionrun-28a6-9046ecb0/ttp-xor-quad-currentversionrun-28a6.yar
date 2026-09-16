rule TTP_XOR_QUAD_CurrentVersionRun_28a6 {
  strings:
    $key_28a6 = { 7b c9 [2] 5f c7 [2] 74 eb [2] 5a c9 [2] 4e d2 [2] 41 c8 [2] 5f d5 [2] 5d d4 [2] 46 d2 [2] 5a d5 [2] 46 fa }

  condition:
    any of them
}