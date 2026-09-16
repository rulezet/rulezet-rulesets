rule TTP_XOR_QUAD_CurrentVersionRun_71a6 {
  strings:
    $key_71a6 = { 22 c9 [2] 06 c7 [2] 2d eb [2] 03 c9 [2] 17 d2 [2] 18 c8 [2] 06 d5 [2] 04 d4 [2] 1f d2 [2] 03 d5 [2] 1f fa }

  condition:
    any of them
}