rule TTP_XOR_QUAD_CurrentVersionRun_159b {
  strings:
    $key_159b = { 46 f4 [2] 62 fa [2] 49 d6 [2] 67 f4 [2] 73 ef [2] 7c f5 [2] 62 e8 [2] 60 e9 [2] 7b ef [2] 67 e8 [2] 7b c7 }

  condition:
    any of them
}