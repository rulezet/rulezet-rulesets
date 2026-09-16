rule TTP_XOR_QUAD_CurrentVersionRun_51a6 {
  strings:
    $key_51a6 = { 02 c9 [2] 26 c7 [2] 0d eb [2] 23 c9 [2] 37 d2 [2] 38 c8 [2] 26 d5 [2] 24 d4 [2] 3f d2 [2] 23 d5 [2] 3f fa }

  condition:
    any of them
}