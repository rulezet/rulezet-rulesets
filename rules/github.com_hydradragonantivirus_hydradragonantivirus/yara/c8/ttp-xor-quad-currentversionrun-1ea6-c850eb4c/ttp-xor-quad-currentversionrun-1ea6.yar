rule TTP_XOR_QUAD_CurrentVersionRun_1ea6 {
  strings:
    $key_1ea6 = { 4d c9 [2] 69 c7 [2] 42 eb [2] 6c c9 [2] 78 d2 [2] 77 c8 [2] 69 d5 [2] 6b d4 [2] 70 d2 [2] 6c d5 [2] 70 fa }

  condition:
    any of them
}