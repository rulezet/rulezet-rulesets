rule TTP_XOR_QUAD_CurrentVersionRun_599b {
  strings:
    $key_599b = { 0a f4 [2] 2e fa [2] 05 d6 [2] 2b f4 [2] 3f ef [2] 30 f5 [2] 2e e8 [2] 2c e9 [2] 37 ef [2] 2b e8 [2] 37 c7 }

  condition:
    any of them
}