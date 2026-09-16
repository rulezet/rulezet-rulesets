rule TTP_XOR_QUAD_CurrentVersionRun_2ea6 {
  strings:
    $key_2ea6 = { 7d c9 [2] 59 c7 [2] 72 eb [2] 5c c9 [2] 48 d2 [2] 47 c8 [2] 59 d5 [2] 5b d4 [2] 40 d2 [2] 5c d5 [2] 40 fa }

  condition:
    any of them
}