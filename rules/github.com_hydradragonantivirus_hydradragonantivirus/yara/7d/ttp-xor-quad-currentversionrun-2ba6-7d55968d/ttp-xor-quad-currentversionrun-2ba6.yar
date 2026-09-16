rule TTP_XOR_QUAD_CurrentVersionRun_2ba6 {
  strings:
    $key_2ba6 = { 78 c9 [2] 5c c7 [2] 77 eb [2] 59 c9 [2] 4d d2 [2] 42 c8 [2] 5c d5 [2] 5e d4 [2] 45 d2 [2] 59 d5 [2] 45 fa }

  condition:
    any of them
}