rule TTP_XOR_QUAD_CurrentVersionRun_459b {
  strings:
    $key_459b = { 16 f4 [2] 32 fa [2] 19 d6 [2] 37 f4 [2] 23 ef [2] 2c f5 [2] 32 e8 [2] 30 e9 [2] 2b ef [2] 37 e8 [2] 2b c7 }

  condition:
    any of them
}