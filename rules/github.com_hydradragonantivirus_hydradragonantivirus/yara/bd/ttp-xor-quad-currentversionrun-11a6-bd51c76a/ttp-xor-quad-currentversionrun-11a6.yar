rule TTP_XOR_QUAD_CurrentVersionRun_11a6 {
  strings:
    $key_11a6 = { 42 c9 [2] 66 c7 [2] 4d eb [2] 63 c9 [2] 77 d2 [2] 78 c8 [2] 66 d5 [2] 64 d4 [2] 7f d2 [2] 63 d5 [2] 7f fa }

  condition:
    any of them
}