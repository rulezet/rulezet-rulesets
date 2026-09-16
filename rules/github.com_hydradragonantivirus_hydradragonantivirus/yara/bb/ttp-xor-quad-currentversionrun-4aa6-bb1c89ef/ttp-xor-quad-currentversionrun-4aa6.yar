rule TTP_XOR_QUAD_CurrentVersionRun_4aa6 {
  strings:
    $key_4aa6 = { 19 c9 [2] 3d c7 [2] 16 eb [2] 38 c9 [2] 2c d2 [2] 23 c8 [2] 3d d5 [2] 3f d4 [2] 24 d2 [2] 38 d5 [2] 24 fa }

  condition:
    any of them
}