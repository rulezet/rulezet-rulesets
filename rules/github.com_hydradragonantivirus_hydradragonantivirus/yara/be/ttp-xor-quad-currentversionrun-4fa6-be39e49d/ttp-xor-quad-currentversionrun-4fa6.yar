rule TTP_XOR_QUAD_CurrentVersionRun_4fa6 {
  strings:
    $key_4fa6 = { 1c c9 [2] 38 c7 [2] 13 eb [2] 3d c9 [2] 29 d2 [2] 26 c8 [2] 38 d5 [2] 3a d4 [2] 21 d2 [2] 3d d5 [2] 21 fa }

  condition:
    any of them
}