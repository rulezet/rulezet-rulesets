rule TTP_XOR_QUAD_CurrentVersionRun_31a6 {
  strings:
    $key_31a6 = { 62 c9 [2] 46 c7 [2] 6d eb [2] 43 c9 [2] 57 d2 [2] 58 c8 [2] 46 d5 [2] 44 d4 [2] 5f d2 [2] 43 d5 [2] 5f fa }

  condition:
    any of them
}