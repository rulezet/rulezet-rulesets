rule TTP_XOR_QUAD_CurrentVersionRun_5ca6 {
  strings:
    $key_5ca6 = { 0f c9 [2] 2b c7 [2] 00 eb [2] 2e c9 [2] 3a d2 [2] 35 c8 [2] 2b d5 [2] 29 d4 [2] 32 d2 [2] 2e d5 [2] 32 fa }

  condition:
    any of them
}