rule TTP_XOR_QUAD_CurrentVersionRun_5ba6 {
  strings:
    $key_5ba6 = { 08 c9 [2] 2c c7 [2] 07 eb [2] 29 c9 [2] 3d d2 [2] 32 c8 [2] 2c d5 [2] 2e d4 [2] 35 d2 [2] 29 d5 [2] 35 fa }

  condition:
    any of them
}