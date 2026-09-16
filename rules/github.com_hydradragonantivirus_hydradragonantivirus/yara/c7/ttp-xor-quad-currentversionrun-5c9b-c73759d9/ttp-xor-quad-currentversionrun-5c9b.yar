rule TTP_XOR_QUAD_CurrentVersionRun_5c9b {
  strings:
    $key_5c9b = { 0f f4 [2] 2b fa [2] 00 d6 [2] 2e f4 [2] 3a ef [2] 35 f5 [2] 2b e8 [2] 29 e9 [2] 32 ef [2] 2e e8 [2] 32 c7 }

  condition:
    any of them
}