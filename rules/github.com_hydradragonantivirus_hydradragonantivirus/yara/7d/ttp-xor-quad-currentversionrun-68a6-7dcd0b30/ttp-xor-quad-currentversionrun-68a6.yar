rule TTP_XOR_QUAD_CurrentVersionRun_68a6 {
  strings:
    $key_68a6 = { 3b c9 [2] 1f c7 [2] 34 eb [2] 1a c9 [2] 0e d2 [2] 01 c8 [2] 1f d5 [2] 1d d4 [2] 06 d2 [2] 1a d5 [2] 06 fa }

  condition:
    any of them
}