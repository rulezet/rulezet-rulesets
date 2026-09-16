rule TTP_XOR_QUAD_CurrentVersionRun_6ca6 {
  strings:
    $key_6ca6 = { 3f c9 [2] 1b c7 [2] 30 eb [2] 1e c9 [2] 0a d2 [2] 05 c8 [2] 1b d5 [2] 19 d4 [2] 02 d2 [2] 1e d5 [2] 02 fa }

  condition:
    any of them
}