rule TTP_XOR_QUAD_CurrentVersionRun_6c9b {
  strings:
    $key_6c9b = { 3f f4 [2] 1b fa [2] 30 d6 [2] 1e f4 [2] 0a ef [2] 05 f5 [2] 1b e8 [2] 19 e9 [2] 02 ef [2] 1e e8 [2] 02 c7 }

  condition:
    any of them
}