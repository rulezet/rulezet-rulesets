rule TTP_XOR_QUAD_CurrentVersionRun_1fa6 {
  strings:
    $key_1fa6 = { 4c c9 [2] 68 c7 [2] 43 eb [2] 6d c9 [2] 79 d2 [2] 76 c8 [2] 68 d5 [2] 6a d4 [2] 71 d2 [2] 6d d5 [2] 71 fa }

  condition:
    any of them
}