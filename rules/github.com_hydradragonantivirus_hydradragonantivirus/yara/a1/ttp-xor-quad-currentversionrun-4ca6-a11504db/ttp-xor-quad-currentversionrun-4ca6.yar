rule TTP_XOR_QUAD_CurrentVersionRun_4ca6 {
  strings:
    $key_4ca6 = { 1f c9 [2] 3b c7 [2] 10 eb [2] 3e c9 [2] 2a d2 [2] 25 c8 [2] 3b d5 [2] 39 d4 [2] 22 d2 [2] 3e d5 [2] 22 fa }

  condition:
    any of them
}