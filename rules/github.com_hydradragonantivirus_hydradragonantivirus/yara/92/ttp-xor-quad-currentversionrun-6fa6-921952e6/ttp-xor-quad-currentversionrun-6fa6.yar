rule TTP_XOR_QUAD_CurrentVersionRun_6fa6 {
  strings:
    $key_6fa6 = { 3c c9 [2] 18 c7 [2] 33 eb [2] 1d c9 [2] 09 d2 [2] 06 c8 [2] 18 d5 [2] 1a d4 [2] 01 d2 [2] 1d d5 [2] 01 fa }

  condition:
    any of them
}