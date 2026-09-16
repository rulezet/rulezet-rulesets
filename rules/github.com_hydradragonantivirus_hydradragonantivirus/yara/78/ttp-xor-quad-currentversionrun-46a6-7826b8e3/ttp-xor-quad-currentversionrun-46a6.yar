rule TTP_XOR_QUAD_CurrentVersionRun_46a6 {
  strings:
    $key_46a6 = { 15 c9 [2] 31 c7 [2] 1a eb [2] 34 c9 [2] 20 d2 [2] 2f c8 [2] 31 d5 [2] 33 d4 [2] 28 d2 [2] 34 d5 [2] 28 fa }

  condition:
    any of them
}