rule TTP_XOR_QUAD_CurrentVersionRun_5fa6 {
  strings:
    $key_5fa6 = { 0c c9 [2] 28 c7 [2] 03 eb [2] 2d c9 [2] 39 d2 [2] 36 c8 [2] 28 d5 [2] 2a d4 [2] 31 d2 [2] 2d d5 [2] 31 fa }

  condition:
    any of them
}