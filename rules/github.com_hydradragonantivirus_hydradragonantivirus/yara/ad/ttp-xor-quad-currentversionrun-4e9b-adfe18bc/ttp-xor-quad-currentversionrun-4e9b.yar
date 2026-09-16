rule TTP_XOR_QUAD_CurrentVersionRun_4e9b {
  strings:
    $key_4e9b = { 1d f4 [2] 39 fa [2] 12 d6 [2] 3c f4 [2] 28 ef [2] 27 f5 [2] 39 e8 [2] 3b e9 [2] 20 ef [2] 3c e8 [2] 20 c7 }

  condition:
    any of them
}