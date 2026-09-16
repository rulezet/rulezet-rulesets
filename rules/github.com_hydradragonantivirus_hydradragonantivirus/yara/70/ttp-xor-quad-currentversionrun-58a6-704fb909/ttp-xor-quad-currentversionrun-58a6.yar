rule TTP_XOR_QUAD_CurrentVersionRun_58a6 {
  strings:
    $key_58a6 = { 0b c9 [2] 2f c7 [2] 04 eb [2] 2a c9 [2] 3e d2 [2] 31 c8 [2] 2f d5 [2] 2d d4 [2] 36 d2 [2] 2a d5 [2] 36 fa }

  condition:
    any of them
}