rule TTP_XOR_QUAD_CurrentVersionRun_2aa6 {
  strings:
    $key_2aa6 = { 79 c9 [2] 5d c7 [2] 76 eb [2] 58 c9 [2] 4c d2 [2] 43 c8 [2] 5d d5 [2] 5f d4 [2] 44 d2 [2] 58 d5 [2] 44 fa }

  condition:
    any of them
}