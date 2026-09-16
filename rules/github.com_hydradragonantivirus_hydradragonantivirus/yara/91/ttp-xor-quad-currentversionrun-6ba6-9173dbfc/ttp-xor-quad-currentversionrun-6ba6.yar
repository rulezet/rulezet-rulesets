rule TTP_XOR_QUAD_CurrentVersionRun_6ba6 {
  strings:
    $key_6ba6 = { 38 c9 [2] 1c c7 [2] 37 eb [2] 19 c9 [2] 0d d2 [2] 02 c8 [2] 1c d5 [2] 1e d4 [2] 05 d2 [2] 19 d5 [2] 05 fa }

  condition:
    any of them
}