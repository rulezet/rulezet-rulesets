rule TTP_XOR_QUAD_CurrentVersionRun_69a6 {
  strings:
    $key_69a6 = { 3a c9 [2] 1e c7 [2] 35 eb [2] 1b c9 [2] 0f d2 [2] 00 c8 [2] 1e d5 [2] 1c d4 [2] 07 d2 [2] 1b d5 [2] 07 fa }

  condition:
    any of them
}