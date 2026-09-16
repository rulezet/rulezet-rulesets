rule TTP_XOR_QUAD_CurrentVersionRun_07a6 {
  strings:
    $key_07a6 = { 54 c9 [2] 70 c7 [2] 5b eb [2] 75 c9 [2] 61 d2 [2] 6e c8 [2] 70 d5 [2] 72 d4 [2] 69 d2 [2] 75 d5 [2] 69 fa }

  condition:
    any of them
}