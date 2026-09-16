rule TTP_XOR_QUAD_CurrentVersionRun_1f9b {
  strings:
    $key_1f9b = { 4c f4 [2] 68 fa [2] 43 d6 [2] 6d f4 [2] 79 ef [2] 76 f5 [2] 68 e8 [2] 6a e9 [2] 71 ef [2] 6d e8 [2] 71 c7 }

  condition:
    any of them
}