rule TTP_XOR_QUAD_CurrentVersionRun_7e9b {
  strings:
    $key_7e9b = { 2d f4 [2] 09 fa [2] 22 d6 [2] 0c f4 [2] 18 ef [2] 17 f5 [2] 09 e8 [2] 0b e9 [2] 10 ef [2] 0c e8 [2] 10 c7 }

  condition:
    any of them
}