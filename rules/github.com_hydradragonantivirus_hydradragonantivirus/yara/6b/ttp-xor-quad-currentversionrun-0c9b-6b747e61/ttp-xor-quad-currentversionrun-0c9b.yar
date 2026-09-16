rule TTP_XOR_QUAD_CurrentVersionRun_0c9b {
  strings:
    $key_0c9b = { 5f f4 [2] 7b fa [2] 50 d6 [2] 7e f4 [2] 6a ef [2] 65 f5 [2] 7b e8 [2] 79 e9 [2] 62 ef [2] 7e e8 [2] 62 c7 }

  condition:
    any of them
}