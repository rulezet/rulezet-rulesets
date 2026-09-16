rule TTP_XOR_QUAD_CurrentVersionRun_00a6 {
  strings:
    $key_00a6 = { 53 c9 [2] 77 c7 [2] 5c eb [2] 72 c9 [2] 66 d2 [2] 69 c8 [2] 77 d5 [2] 75 d4 [2] 6e d2 [2] 72 d5 [2] 6e fa }

  condition:
    any of them
}