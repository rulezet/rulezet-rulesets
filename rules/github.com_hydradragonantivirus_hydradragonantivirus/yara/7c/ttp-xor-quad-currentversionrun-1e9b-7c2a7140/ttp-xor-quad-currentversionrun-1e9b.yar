rule TTP_XOR_QUAD_CurrentVersionRun_1e9b {
  strings:
    $key_1e9b = { 4d f4 [2] 69 fa [2] 42 d6 [2] 6c f4 [2] 78 ef [2] 77 f5 [2] 69 e8 [2] 6b e9 [2] 70 ef [2] 6c e8 [2] 70 c7 }

  condition:
    any of them
}